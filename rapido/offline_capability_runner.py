"""Completion-driven supervision for one unchanged offline solver flow.

The runner deliberately does not schedule tasks or call a checker.  A CAP-02 Board/runtime
adapter drives the existing :class:`DurableJobControl` once and exposes only closed evidence via
``CapabilityFlow.snapshot``.  This module owns the outer wall cap, settlement, denominator
preservation, candidate-free projection, and cleanup deadline.

The receipt is an internal sanitized runner receipt.  It is intentionally distinct from the
frozen public capability receipt: source/configuration commitments and human decisions belong to
the pure public assembler.  No candidate value or candidate-derived identity has a schema slot.
"""

from __future__ import annotations

import asyncio
import ctypes
import importlib
import ipaddress
import json
import math
import os
import pickle
import re
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Protocol

from .board import BoardLike
from .config import RuntimeConfig
from .control import DurableJobControl
from .offline_capability_schema import (
    EXPERIMENT_DENOMINATOR_CONTRACTS,
    EXPERIMENT_NUMERICS,
    MODEL_DESCRIPTOR_PAIRS,
    PROVIDER_ATTEMPT_STATUSES,
    ROUTING_CONTRACTS,
    SENTINEL_IDS,
    TERMINAL_LABELS,
    TOOL_FAILURE_LABELS,
)
from .orchestrator import NativeRuntime, RunReport

RUNNER_RECEIPT_SCHEMA = "rapido-offline-capability-runner-v1"
SUPERVISOR_MESSAGE_SCHEMA = "rapido-offline-capability-supervisor-message-v1"
_CANCEL_DRAIN_SECONDS = 1.0
_MAX_SUPERVISOR_REQUEST_BYTES = 262_144
_MAX_SUPERVISOR_RESPONSE_BYTES = 4_194_304
_SUPERVISOR_POLL_SECONDS = 0.01
_SUPERVISOR_TERM_SECONDS = 0.25
_SUPERVISOR_EXIT_SECONDS = 0.25
_WORKER_READY_SECONDS = 30.0
_DURABLE_FACTORY_PATH = "rapido.offline_capability_runtime:registered_durable_flow_factory"
_LOCAL_PROBE_FACTORY_PATH = "tests.test_offline_capability_runner:registered_probe_flow_factory"
_APPROVED_PROVIDER_AUTH_FACTORIES = frozenset({_DURABLE_FACTORY_PATH})
_PRIVATE_RUNTIME_ROOT_ENV = "RAPIDO_OFFLINE_CAPABILITY_ROOT"
_PRIVATE_RUNTIME_REGISTRY_DIGEST_ENV = "RAPIDO_OFFLINE_CAPABILITY_REGISTRY_SHA256"
_APPROVED_FACTORY_ENVIRONMENT = {
    _DURABLE_FACTORY_PATH: frozenset(
        {"CODEX_HOME", _PRIVATE_RUNTIME_ROOT_ENV, _PRIVATE_RUNTIME_REGISTRY_DIGEST_ENV}
    ),
    _LOCAL_PROBE_FACTORY_PATH: frozenset(),
}
_CONTAINMENT_KILLED_EXIT = 247
_LINUX_SUPERVISOR_LOCK = threading.Lock()
_TASK_ID = re.compile(r"[A-Z0-9-]{3,80}\Z")
_CLOSED_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,119}\Z")
_RUN_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,79}\Z")
_IMPORT_PATH = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
    r":[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*\Z"
)
_FORBIDDEN_PUBLIC_KEY = re.compile(
    r"(?:answer|expected_answer|flag|candidate_(?:value|bytes|digest|hash|sha256)|answer_digest|"
    r"oracle_key|credential|api_key|access_token|refresh_token|host_path|target_authority|"
    r"raw_(?:private_payload|model_output|tool_payload|output)|token|secret)\Z",
    re.IGNORECASE,
)
_FORBIDDEN_PUBLIC_VALUE = re.compile(
    r"(?:INCYPHER\{|flag\{|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|"
    r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|"
    r"(?:https?|wss?)://|\b(?:localhost|127\.0\.0\.1|\[::1\])(?::\d+)?\b|"
    r"(?<![A-Za-z0-9])(?:~|\$HOME)/[^\s>`'\"]+|"
    r"(?<![<A-Za-z0-9])/(?!/)[^\s>`'\"]+|"
    r"(?:^|\s)[A-Za-z]:[\\/][^\s>`'\"]+|(?:^|\s)(?:\\\\|//)[^\s>`'\"]+|"
    r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?::[0-9]{2,5})?\b|"
    r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{2,5})?\b|"
    r"(?<![A-Za-z0-9_:])[0-9a-f]{40,64}(?![A-Za-z0-9_]))",
    re.IGNORECASE,
)
_CHECK_RESULTS = frozenset({"correct", "incorrect", "inconclusive"})
_TOOL_STATUSES = frozenset({"completed", "failed", "cancelled"})


class CapabilityRunnerError(ValueError):
    """Closed runner evidence is internally inconsistent."""


class CapabilitySupervisorError(RuntimeError):
    """The disposable runner worker failed without returning private detail."""

    def __init__(
        self,
        failure_label: str,
        *,
        terminated: bool,
        killed: bool,
        child_reaped: bool,
        child_absent: bool,
    ) -> None:
        _closed_id(failure_label, "supervisor failure label")
        if any(
            type(value) is not bool for value in (terminated, killed, child_reaped, child_absent)
        ):
            raise CapabilityRunnerError("supervisor process evidence is invalid")
        if child_absent and not child_reaped:
            raise CapabilityRunnerError("supervisor absence lacks exact child reaping")
        super().__init__(failure_label)
        self.failure_label = failure_label
        self.terminated = terminated
        self.killed = killed
        self.child_reaped = child_reaped
        self.child_absent = child_absent


def _closed_id(value: str, label: str) -> str:
    if type(value) is not str or _CLOSED_ID.fullmatch(value) is None:
        raise CapabilityRunnerError(f"{label} is not a closed identifier")
    return value


def _offset(value: int | None, label: str) -> int | None:
    if value is not None and (type(value) is not int or value < 0):
        raise CapabilityRunnerError(f"{label} is not a nonnegative millisecond offset")
    return value


@dataclass(frozen=True)
class Usage:
    input: int | None = None
    cached_input: int | None = None
    output: int | None = None
    reasoning: int | None = None

    def __post_init__(self) -> None:
        for name, value in self.public().items():
            if value is not None and (type(value) is not int or value < 0):
                raise CapabilityRunnerError(f"usage.{name} is invalid")

    def public(self) -> dict[str, int | None]:
        return {
            "input": self.input,
            "cached_input": self.cached_input,
            "output": self.output,
            "reasoning": self.reasoning,
        }


@dataclass(frozen=True)
class ResourceObservation:
    cpu_peak_cores: float | None = None
    memory_peak_bytes: int | None = None
    pids_peak: int | None = None
    disk_peak_bytes: int | None = None
    unavailable_reason: str | None = "not_observed"

    def __post_init__(self) -> None:
        numeric = (
            self.cpu_peak_cores,
            self.memory_peak_bytes,
            self.pids_peak,
            self.disk_peak_bytes,
        )
        if self.cpu_peak_cores is not None and (
            isinstance(self.cpu_peak_cores, bool)
            or not isinstance(self.cpu_peak_cores, (int, float))
            or not math.isfinite(float(self.cpu_peak_cores))
            or self.cpu_peak_cores < 0
        ):
            raise CapabilityRunnerError("resource CPU sample is invalid")
        for value in numeric[1:]:
            if value is not None and (type(value) is not int or value < 0):
                raise CapabilityRunnerError("resource sample is invalid")
        missing = any(value is None for value in numeric)
        if missing is not (self.unavailable_reason is not None):
            raise CapabilityRunnerError("resource null/reason semantics are inconsistent")
        if self.unavailable_reason is not None:
            _closed_id(self.unavailable_reason, "resource unavailable reason")

    def public(self) -> dict[str, object]:
        return {
            "cpu_peak_cores": self.cpu_peak_cores,
            "memory_peak_bytes": self.memory_peak_bytes,
            "pids_peak": self.pids_peak,
            "disk_peak_bytes": self.disk_peak_bytes,
            "unavailable_reason": self.unavailable_reason,
        }


@dataclass(frozen=True)
class TaskRegistration:
    task_id: str
    family_id: str
    category: str
    tier: str
    checker_version: str
    generator_version: str = "generator-v1"
    service_version: str = "none"

    def __post_init__(self) -> None:
        if type(self.task_id) is not str or _TASK_ID.fullmatch(self.task_id) is None:
            raise CapabilityRunnerError("task ID is invalid")
        _closed_id(self.family_id, "family ID")
        _closed_id(self.category, "category")
        _closed_id(self.checker_version, "checker version")
        _closed_id(self.generator_version, "generator version")
        _closed_id(self.service_version, "service version")
        if self.tier not in {"A", "B", "C", "sentinel"}:
            raise CapabilityRunnerError("task tier is invalid")


@dataclass(frozen=True)
class ModelDescriptor:
    model: str
    effort: str

    def __post_init__(self) -> None:
        _closed_id(self.model, "model")
        _closed_id(self.effort, "effort")


@dataclass(frozen=True)
class UsageCaps:
    input: int
    output: int
    reasoning: int

    def __post_init__(self) -> None:
        for name, value in (
            ("input", self.input),
            ("output", self.output),
            ("reasoning", self.reasoning),
        ):
            if type(value) is not int or value < 0:
                raise CapabilityRunnerError(f"usage cap {name} is invalid")


def _mixed_lanes() -> tuple[ModelDescriptor, ...]:
    return (
        ModelDescriptor("gpt-daybreak-blue-latest", "xhigh"),
        ModelDescriptor("gpt-daybreak-blue-latest", "xhigh"),
        ModelDescriptor("gpt-5.6-luna", "max"),
        ModelDescriptor("gpt-5.6-luna", "xhigh"),
    )


def _daybreak_lanes() -> tuple[ModelDescriptor, ...]:
    return (ModelDescriptor("gpt-daybreak-blue-latest", "xhigh"),) * 4


@dataclass(frozen=True)
class ExecutionPolicy:
    routing_profile: str = "mixed_v1"
    lane_descriptors: tuple[ModelDescriptor, ...] = field(default_factory=_mixed_lanes)
    active_challenges: int = 5
    lane_admissions: int = 20
    dynamic_leases: int = 1
    attempts_per_task: int = 4
    episodes_per_task: int = 3
    attempt_seconds: int = 800
    usage_caps: UsageCaps = field(
        default_factory=lambda: UsageCaps(input=20_000_000, output=1_000_000, reasoning=600_000)
    )

    def __post_init__(self) -> None:
        _closed_id(self.routing_profile, "routing profile")
        if not self.lane_descriptors or len(self.lane_descriptors) != self.attempts_per_task:
            raise CapabilityRunnerError("lane descriptor count changed")
        if (
            self.active_challenges,
            self.lane_admissions,
            self.dynamic_leases,
            self.attempts_per_task,
            self.episodes_per_task,
            self.attempt_seconds,
        ) != (5, 20, 1, 4, 3, 800):
            raise CapabilityRunnerError("execution policy changed the frozen scheduler caps")
        mixed_profiles = {
            "preflight_v1",
            "mixed_v1",
            "rte_mixed_v1",
            "rte_optional_stage_category_v1",
            "selected_mixed_v1",
        }
        daybreak_profiles = {"rte_daybreak_v1", "selected_daybreak_v1"}
        expected_lanes = (
            _mixed_lanes()
            if self.routing_profile in mixed_profiles
            else _daybreak_lanes()
            if self.routing_profile in daybreak_profiles
            else None
        )
        if expected_lanes is None or self.lane_descriptors != expected_lanes:
            raise CapabilityRunnerError("execution policy roster is not frozen")

    def public(self) -> dict[str, object]:
        return {
            "routing_profile": self.routing_profile,
            "lane_descriptors": [
                {"model": descriptor.model, "effort": descriptor.effort}
                for descriptor in self.lane_descriptors
            ],
            "active_challenges": self.active_challenges,
            "lane_admissions": self.lane_admissions,
            "dynamic_leases": self.dynamic_leases,
            "attempts_per_task": self.attempts_per_task,
            "episodes_per_task": self.episodes_per_task,
            "attempt_seconds": self.attempt_seconds,
            "usage_caps": {
                "input": self.usage_caps.input,
                "output": self.usage_caps.output,
                "reasoning": self.usage_caps.reasoning,
            },
            "fallback_allowed": False,
        }


@dataclass(frozen=True)
class ProviderAttempt:
    lane: int
    requested_model: str
    requested_effort: str
    effective_model: str | None
    effective_effort: str | None
    effective_revision_build: str | None
    native_client_version: str
    status: str
    started_ms: int
    ended_ms: int
    usage: Usage = field(default_factory=Usage)

    def __post_init__(self) -> None:
        if type(self.lane) is not int or self.lane < 0:
            raise CapabilityRunnerError("provider lane is invalid")
        for label, value in (
            ("requested model", self.requested_model),
            ("requested effort", self.requested_effort),
            ("native client version", self.native_client_version),
        ):
            _closed_id(value, label)
        for label, value in (
            ("effective model", self.effective_model),
            ("effective effort", self.effective_effort),
            ("effective revision", self.effective_revision_build),
        ):
            if value is not None:
                _closed_id(value, label)
        if self.status not in PROVIDER_ATTEMPT_STATUSES:
            raise CapabilityRunnerError("provider status is invalid")
        _offset(self.started_ms, "provider start")
        _offset(self.ended_ms, "provider end")
        if self.ended_ms < self.started_ms:
            raise CapabilityRunnerError("provider offsets are out of order")
        if self.status == "completed" and (
            self.effective_model is None
            or self.effective_effort is None
            or self.effective_revision_build is None
        ):
            raise CapabilityRunnerError("completed provider attempt lacks an effective descriptor")

    def public(self, ordinal: int) -> dict[str, object]:
        return {
            "ordinal": ordinal,
            "lane": self.lane,
            "requested_model": self.requested_model,
            "requested_effort": self.requested_effort,
            "effective_model": self.effective_model,
            "effective_effort": self.effective_effort,
            "effective_revision_build": self.effective_revision_build,
            "native_client_version": self.native_client_version,
            "status": self.status,
            "started_ms": self.started_ms,
            "ended_ms": self.ended_ms,
            "usage": self.usage.public(),
        }


@dataclass(frozen=True)
class CandidateCheck:
    candidate_returned_ms: int
    checker_started_ms: int
    checker_ended_ms: int
    result: str

    def __post_init__(self) -> None:
        for label, value in (
            ("candidate return", self.candidate_returned_ms),
            ("checker start", self.checker_started_ms),
            ("checker end", self.checker_ended_ms),
        ):
            _offset(value, label)
        if not self.candidate_returned_ms <= self.checker_started_ms <= self.checker_ended_ms:
            raise CapabilityRunnerError("candidate/checker offsets are out of order")
        if self.result not in _CHECK_RESULTS:
            raise CapabilityRunnerError("checker result is invalid")

    def public(self, ordinal: int) -> dict[str, object]:
        return {
            "ordinal": ordinal,
            "candidate_returned_ms": self.candidate_returned_ms,
            "checker_started_ms": self.checker_started_ms,
            "checker_ended_ms": self.checker_ended_ms,
            "result": self.result,
        }


@dataclass(frozen=True)
class CheckerCandidateAttestation:
    task_id: str
    checker_version: str
    ordinal: int
    result: str
    repeat_count: int

    def __post_init__(self) -> None:
        if type(self.task_id) is not str or _TASK_ID.fullmatch(self.task_id) is None:
            raise CapabilityRunnerError("checker attestation task ID is invalid")
        _closed_id(self.checker_version, "checker attestation checker version")
        if type(self.ordinal) is not int or self.ordinal <= 0:
            raise CapabilityRunnerError("checker attestation ordinal is invalid")
        if self.result not in _CHECK_RESULTS:
            raise CapabilityRunnerError("checker attestation result is invalid")
        if type(self.repeat_count) is not int or self.repeat_count < 0:
            raise CapabilityRunnerError("checker attestation repeat count is invalid")

    def public(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "checker_version": self.checker_version,
            "ordinal": self.ordinal,
            "result": self.result,
            "repeat_count": self.repeat_count,
        }


@dataclass(frozen=True)
class CheckerEconomyAttestation:
    source: str
    cache_scope: str
    unique_candidate_count: int
    repeat_candidate_count: int
    checker_call_count: int
    candidates: tuple[CheckerCandidateAttestation, ...]

    def __post_init__(self) -> None:
        if self.source != "offline_board_private_cache_v1" or self.cache_scope != "run_local":
            raise CapabilityRunnerError("checker economy attestation source is invalid")
        for value in (
            self.unique_candidate_count,
            self.repeat_candidate_count,
            self.checker_call_count,
        ):
            if type(value) is not int or value < 0:
                raise CapabilityRunnerError("checker economy count is invalid")
        if (
            self.unique_candidate_count != len(self.candidates)
            or self.checker_call_count != self.unique_candidate_count
            or self.repeat_candidate_count != sum(row.repeat_count for row in self.candidates)
        ):
            raise CapabilityRunnerError("checker economy attestation is inconsistent")
        by_task: dict[str, list[int]] = {}
        for row in self.candidates:
            by_task.setdefault(row.task_id, []).append(row.ordinal)
        if any(ordinals != list(range(1, len(ordinals) + 1)) for ordinals in by_task.values()):
            raise CapabilityRunnerError("checker attestation ordinals are not contiguous")

    @classmethod
    def empty(cls) -> CheckerEconomyAttestation:
        return cls("offline_board_private_cache_v1", "run_local", 0, 0, 0, ())

    @classmethod
    def from_offline_board_snapshot(
        cls,
        snapshot: Mapping[str, object],
        registrations: Sequence[TaskRegistration],
    ) -> CheckerEconomyAttestation:
        expected = {
            "unique_candidate_count",
            "repeat_candidate_count",
            "checker_call_count",
            "candidates",
        }
        if not expected <= set(snapshot):
            raise CapabilityRunnerError("offline Board snapshot lacks checker cache evidence")
        raw_registrations = snapshot.get("task_registrations")
        if not isinstance(raw_registrations, Sequence) or isinstance(
            raw_registrations, (str, bytes)
        ):
            raise CapabilityRunnerError("offline Board snapshot lacks frozen task registrations")
        frozen = tuple(
            (
                task.task_id,
                task.generator_version,
                task.checker_version,
                task.service_version,
            )
            for task in registrations
        )
        observed: list[tuple[object, object, object, object]] = []
        observed_ids: set[str] = set()
        for raw_registration in raw_registrations:
            if not isinstance(raw_registration, Mapping):
                raise CapabilityRunnerError("offline Board task registration is invalid")
            task_id = raw_registration.get("task_id")
            if not isinstance(task_id, str) or task_id in observed_ids:
                raise CapabilityRunnerError("offline Board task registration is invalid")
            observed_ids.add(task_id)
            observed.append(
                (
                    task_id,
                    raw_registration.get("generator_version"),
                    raw_registration.get("checker_version"),
                    raw_registration.get("service_version"),
                )
            )
        if tuple(observed) != frozen:
            raise CapabilityRunnerError("offline Board task registration changed")
        raw_candidates = snapshot["candidates"]
        if not isinstance(raw_candidates, Sequence) or isinstance(raw_candidates, (str, bytes)):
            raise CapabilityRunnerError("offline Board candidate attestation is invalid")
        candidates: list[CheckerCandidateAttestation] = []
        checker_versions = {task.task_id: task.checker_version for task in registrations}
        for raw in raw_candidates:
            if not isinstance(raw, Mapping) or set(raw) != {
                "task_id",
                "candidate_ordinal",
                "outcome",
                "repeat_count",
            }:
                raise CapabilityRunnerError("offline Board candidate row is invalid")
            outcome = raw["outcome"]
            result = "inconclusive" if outcome == "oracle_inconclusive" else outcome
            candidates.append(
                CheckerCandidateAttestation(
                    task_id=raw["task_id"],  # type: ignore[arg-type]
                    checker_version=checker_versions.get(raw["task_id"], ""),
                    ordinal=raw["candidate_ordinal"],  # type: ignore[arg-type]
                    result=result,  # type: ignore[arg-type]
                    repeat_count=raw["repeat_count"],  # type: ignore[arg-type]
                )
            )
        return cls(
            source="offline_board_private_cache_v1",
            cache_scope="run_local",
            unique_candidate_count=snapshot["unique_candidate_count"],  # type: ignore[arg-type]
            repeat_candidate_count=snapshot["repeat_candidate_count"],  # type: ignore[arg-type]
            checker_call_count=snapshot["checker_call_count"],  # type: ignore[arg-type]
            candidates=tuple(candidates),
        )

    def public(self) -> dict[str, object]:
        return {
            "source": self.source,
            "cache_scope": self.cache_scope,
            "unique_candidate_count": self.unique_candidate_count,
            "repeat_candidate_count": self.repeat_candidate_count,
            "checker_call_count": self.checker_call_count,
            "candidates": [row.public() for row in self.candidates],
        }


@dataclass(frozen=True)
class ToolAttempt:
    status: str
    started_ms: int
    ended_ms: int
    failure_label: str | None = None

    def __post_init__(self) -> None:
        if self.status not in _TOOL_STATUSES:
            raise CapabilityRunnerError("tool status is invalid")
        _offset(self.started_ms, "tool start")
        _offset(self.ended_ms, "tool end")
        if self.ended_ms < self.started_ms:
            raise CapabilityRunnerError("tool offsets are out of order")
        if self.status == "failed":
            if self.failure_label not in TOOL_FAILURE_LABELS:
                raise CapabilityRunnerError("failed tool call lacks a closed label")
        elif self.failure_label is not None:
            raise CapabilityRunnerError("non-failed tool call has a failure label")

    def public(self, ordinal: int) -> dict[str, object]:
        return {
            "ordinal": ordinal,
            "status": self.status,
            "started_ms": self.started_ms,
            "ended_ms": self.ended_ms,
            "failure_label": self.failure_label,
        }


@dataclass(frozen=True)
class IndependentVerification:
    started_ms: int
    ended_ms: int
    result: str
    method_version: str

    def __post_init__(self) -> None:
        _offset(self.started_ms, "independent verification start")
        _offset(self.ended_ms, "independent verification end")
        if self.ended_ms < self.started_ms or self.result not in _CHECK_RESULTS:
            raise CapabilityRunnerError("independent verification is invalid")
        _closed_id(self.method_version, "independent verification method")

    def public(self) -> dict[str, object]:
        return {
            "started_ms": self.started_ms,
            "ended_ms": self.ended_ms,
            "result": self.result,
            "method_version": self.method_version,
        }


@dataclass(frozen=True)
class TaskEvidence:
    admitted_ms: int | None = None
    started_ms: int | None = None
    terminal_ms: int | None = None
    terminal_label: str | None = None
    candidate_checks: tuple[CandidateCheck, ...] = ()
    candidate_repeat_count: int = 0
    provider_attempts: tuple[ProviderAttempt, ...] = ()
    tool_attempts: tuple[ToolAttempt, ...] = ()
    qualification: str = "not_applicable"
    qualification_ms: int | None = None
    qualification_rejection_stage: str | None = None
    independent_verification: IndependentVerification | None = None
    resources: ResourceObservation = field(default_factory=ResourceObservation)
    cleanup_passed: bool | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("admission", self.admitted_ms),
            ("start", self.started_ms),
            ("terminal", self.terminal_ms),
            ("qualification", self.qualification_ms),
        ):
            _offset(value, label)
        times = [value for value in (self.admitted_ms, self.started_ms) if value is not None]
        if times != sorted(times):
            raise CapabilityRunnerError("task admission/start offsets are out of order")
        if self.started_ms is not None and self.admitted_ms is None:
            raise CapabilityRunnerError("task started without admission")
        if (self.terminal_ms is None) is not (self.terminal_label is None):
            raise CapabilityRunnerError("task terminal label/offset mismatch")
        if self.terminal_label is not None and self.terminal_label not in TERMINAL_LABELS:
            raise CapabilityRunnerError("task terminal label is invalid")
        if self.terminal_ms is not None and any(
            value is not None and self.terminal_ms < value
            for value in (self.admitted_ms, self.started_ms, self.qualification_ms)
        ):
            raise CapabilityRunnerError("task terminal precedes lifecycle evidence")
        if (
            self.qualification_ms is not None
            and self.started_ms is not None
            and self.qualification_ms < self.started_ms
        ):
            raise CapabilityRunnerError("task qualification precedes start")
        if type(self.candidate_repeat_count) is not int or self.candidate_repeat_count < 0:
            raise CapabilityRunnerError("candidate repeat count is invalid")
        if self.qualification not in {"accepted", "rejected", "not_applicable", "inconclusive"}:
            raise CapabilityRunnerError("qualification result is invalid")
        if (self.qualification in {"accepted", "rejected"}) is not (
            self.qualification_ms is not None
        ):
            raise CapabilityRunnerError("qualification result/offset mismatch")
        if (self.qualification == "rejected") is not (
            self.qualification_rejection_stage is not None
        ):
            raise CapabilityRunnerError("qualification rejection stage mismatch")
        if self.qualification_rejection_stage is not None:
            _closed_id(self.qualification_rejection_stage, "qualification rejection stage")
        if self.cleanup_passed is not None and type(self.cleanup_passed) is not bool:
            raise CapabilityRunnerError("task cleanup result is invalid")
        if (
            self.started_ms is not None
            and self.terminal_ms is not None
            and self.cleanup_passed is None
        ):
            raise CapabilityRunnerError("terminal started task lacks cleanup evidence")
        returns = [check.candidate_returned_ms for check in self.candidate_checks]
        if returns != sorted(returns):
            raise CapabilityRunnerError("candidate ordinals are not chronological")
        if self.started_ms is None and (
            self.candidate_checks or self.provider_attempts or self.tool_attempts
        ):
            raise CapabilityRunnerError("unstarted task contains execution evidence")
        if self.started_ms is not None:
            starts = [
                *(attempt.started_ms for attempt in self.provider_attempts),
                *(check.candidate_returned_ms for check in self.candidate_checks),
                *(check.checker_started_ms for check in self.candidate_checks),
                *(attempt.started_ms for attempt in self.tool_attempts),
            ]
            if self.independent_verification is not None:
                starts.append(self.independent_verification.started_ms)
            if any(start < self.started_ms for start in starts):
                raise CapabilityRunnerError("execution evidence precedes task start")
        if self.terminal_ms is not None:
            ends = [
                *(attempt.ended_ms for attempt in self.provider_attempts),
                *(check.checker_ended_ms for check in self.candidate_checks),
                *(attempt.ended_ms for attempt in self.tool_attempts),
            ]
            if self.independent_verification is not None:
                ends.append(self.independent_verification.ended_ms)
            if any(end > self.terminal_ms for end in ends):
                raise CapabilityRunnerError("task evidence exceeds its terminal offset")
        correct = any(check.result == "correct" for check in self.candidate_checks)
        if self.terminal_label is not None and (self.terminal_label == "correct") is not correct:
            raise CapabilityRunnerError("correct terminal/checker evidence mismatch")
        if self.qualification in {"accepted", "rejected"} and not correct:
            raise CapabilityRunnerError("qualification decision lacks raw correctness")
        if (
            self.independent_verification is not None
            and self.independent_verification.result == "correct"
            and not correct
        ):
            raise CapabilityRunnerError("independent correctness lacks raw correctness")
        if self.terminal_label == "oracle_inconclusive" and not any(
            check.result == "inconclusive" for check in self.candidate_checks
        ):
            raise CapabilityRunnerError("oracle terminal lacks inconclusive checker evidence")
        if self.terminal_label == "incorrect" and not any(
            check.result == "incorrect" for check in self.candidate_checks
        ):
            raise CapabilityRunnerError("incorrect terminal lacks checker evidence")
        provider_terminal = {
            "provider_failure": "provider_failure",
            "provider_unavailable": "provider_unavailable",
            "descriptor_mismatch": "descriptor_mismatch",
        }.get(self.terminal_label)
        if provider_terminal is not None and not any(
            attempt.status == provider_terminal for attempt in self.provider_attempts
        ):
            raise CapabilityRunnerError("provider terminal lacks matching attempt evidence")
        if self.terminal_label in TOOL_FAILURE_LABELS and not any(
            attempt.status == "failed" and attempt.failure_label == self.terminal_label
            for attempt in self.tool_attempts
        ):
            raise CapabilityRunnerError("tool terminal lacks matching attempt evidence")
        if self.terminal_label == "no_unique_candidate" and (
            self.candidate_checks or self.candidate_repeat_count
        ):
            raise CapabilityRunnerError("no-candidate terminal contradicts candidate evidence")
        if self.terminal_label == "repeated_candidate_only" and (
            self.candidate_checks or self.candidate_repeat_count == 0
        ):
            raise CapabilityRunnerError("repeated-only terminal contradicts candidate evidence")
        if (
            self.terminal_label in {"unstarted_at_cap", "queued_at_cap"}
            and self.started_ms is not None
        ):
            raise CapabilityRunnerError("unstarted terminal contradicts task lifecycle")
        if self.terminal_label == "queued_at_cap" and self.admitted_ms is None:
            raise CapabilityRunnerError("queued terminal lacks admission evidence")
        if self.terminal_label == "unstarted_at_cap" and self.admitted_ms is not None:
            raise CapabilityRunnerError("unstarted terminal contradicts admission evidence")
        if self.terminal_label in {"attempt_timeout", "global_cap", "usage_cap"} and (
            self.started_ms is None
        ):
            raise CapabilityRunnerError("running terminal lacks task lifecycle")
        if self.terminal_label == "cleanup_failure" and self.cleanup_passed is not False:
            raise CapabilityRunnerError("cleanup terminal/result mismatch")

    def public(self, registration: TaskRegistration) -> dict[str, object]:
        checks = [check.public(index) for index, check in enumerate(self.candidate_checks, 1)]
        correct_ends = [
            check.checker_ended_ms for check in self.candidate_checks if check.result == "correct"
        ]
        first_correct = min(correct_ends) if correct_ends else None
        raw_correct: bool | None
        if first_correct is not None:
            raw_correct = True
        elif any(check.result == "incorrect" for check in self.candidate_checks):
            raw_correct = False
        else:
            raw_correct = None
        usage = _sum_usage(tuple(attempt.usage for attempt in self.provider_attempts))
        provider_failures = sum(
            attempt.status in {"provider_failure", "provider_unavailable", "descriptor_mismatch"}
            for attempt in self.provider_attempts
        )
        verification = self.independent_verification
        return {
            "task_id": registration.task_id,
            "family_id": registration.family_id,
            "category": registration.category,
            "tier": registration.tier,
            "started": self.started_ms is not None,
            "admitted_ms": self.admitted_ms,
            "started_ms": self.started_ms,
            "first_unique_candidate_ms": (
                None
                if not self.candidate_checks
                else self.candidate_checks[0].candidate_returned_ms
            ),
            "first_correct_ms": first_correct,
            "terminal_ms": self.terminal_ms,
            "terminal_label": self.terminal_label,
            "raw_correct": raw_correct,
            "qualification": self.qualification,
            "qualification_ms": self.qualification_ms,
            "qualification_rejection_stage": self.qualification_rejection_stage,
            "independent_check": "not_invoked" if verification is None else verification.result,
            "independent_verification": None if verification is None else verification.public(),
            "candidate_unique_count": len(checks),
            "candidate_repeat_count": self.candidate_repeat_count,
            "checker_call_count": len(checks),
            "provider_invocation_count": len(self.provider_attempts),
            "provider_failure_count": provider_failures,
            "provider_attempts": [
                attempt.public(index) for index, attempt in enumerate(self.provider_attempts, 1)
            ],
            "candidate_checks": checks,
            "checker_version": registration.checker_version,
            "generator_version": registration.generator_version,
            "service_version": registration.service_version,
            "usage": usage.public(),
            "resources": self.resources.public(),
            "tool_call_count": len(self.tool_attempts),
            "tool_attempts": [
                attempt.public(index) for index, attempt in enumerate(self.tool_attempts, 1)
            ],
            "tool_failure_labels": [
                attempt.failure_label for attempt in self.tool_attempts if attempt.failure_label
            ],
            "cleanup_passed": self.cleanup_passed,
        }


@dataclass(frozen=True)
class ServiceAttempt:
    service_id: str
    task_id: str
    status: str
    started_ms: int
    ready_ms: int | None
    ended_ms: int
    failure_label: str | None = None

    def __post_init__(self) -> None:
        _closed_id(self.service_id, "service ID")
        if type(self.task_id) is not str or _TASK_ID.fullmatch(self.task_id) is None:
            raise CapabilityRunnerError("service task ID is invalid")
        if self.status not in {"stopped", "start_failure", "unready", "lost", "cancelled"}:
            raise CapabilityRunnerError("service status is invalid")
        for label, value in (
            ("service start", self.started_ms),
            ("service ready", self.ready_ms),
            ("service end", self.ended_ms),
        ):
            _offset(value, label)
        if self.ended_ms < self.started_ms or (
            self.ready_ms is not None and not self.started_ms <= self.ready_ms <= self.ended_ms
        ):
            raise CapabilityRunnerError("service offsets are out of order")
        if self.failure_label is not None:
            _closed_id(self.failure_label, "service failure label")
        expected_failure = {
            "start_failure": "service_start_failure",
            "unready": "service_unready",
            "lost": "service_lost",
        }.get(self.status)
        if self.failure_label != expected_failure:
            raise CapabilityRunnerError("service status/failure label mismatch")

    def public(self, ordinal: int) -> dict[str, object]:
        return {
            "ordinal": ordinal,
            "task_id": self.task_id,
            "status": self.status,
            "started_ms": self.started_ms,
            "ready_ms": self.ready_ms,
            "ended_ms": self.ended_ms,
            "failure_label": self.failure_label,
        }


@dataclass(frozen=True)
class FlowEvidence:
    tasks: Mapping[str, TaskEvidence]
    checker_attestation: CheckerEconomyAttestation = field(
        default_factory=CheckerEconomyAttestation.empty
    )
    service_attempts: tuple[ServiceAttempt, ...] = ()
    resources: ResourceObservation = field(default_factory=ResourceObservation)


@dataclass(frozen=True)
class CleanupInventory:
    processes: int | None
    containers: int | None
    volumes: int | None
    networks: int | None
    services: int | None
    workspaces: int | None
    state_objects: int | None
    run_ids: int | None
    failure_label: str | None = None

    def __post_init__(self) -> None:
        for value in self.counts():
            if value is not None and (type(value) is not int or value < 0):
                raise CapabilityRunnerError("cleanup inventory count is invalid")
        unavailable = any(value is None for value in self.counts())
        residue = any(value for value in self.counts() if value is not None)
        if (unavailable or residue) and self.failure_label is None:
            raise CapabilityRunnerError("incomplete cleanup requires a failure label")
        if self.failure_label is not None:
            _closed_id(self.failure_label, "cleanup failure label")

    @classmethod
    def unavailable(cls) -> CleanupInventory:
        return cls(*(None for _ in range(8)), failure_label="cleanup_inventory_unavailable")

    def counts(self) -> tuple[int | None, ...]:
        return (
            self.processes,
            self.containers,
            self.volumes,
            self.networks,
            self.services,
            self.workspaces,
            self.state_objects,
            self.run_ids,
        )

    def public(self) -> dict[str, object]:
        passed = self.failure_label is None and all(value == 0 for value in self.counts())
        return {
            "passed": passed,
            "failure_label": self.failure_label,
            "inventory_complete": all(value is not None for value in self.counts()),
            "owned_processes_remaining": self.processes,
            "owned_containers_remaining": self.containers,
            "owned_volumes_remaining": self.volumes,
            "owned_networks_remaining": self.networks,
            "owned_services_remaining": self.services,
            "owned_workspaces_remaining": self.workspaces,
            "owned_state_objects_remaining": self.state_objects,
            "owned_run_ids_remaining": self.run_ids,
        }


@dataclass(frozen=True)
class RunnerContract:
    run_id: str
    experiment_id: str
    tasks: tuple[TaskRegistration, ...]
    scoring_seconds: float
    settlement_seconds: float = 180.0
    cleanup_grace_seconds: float = 190.0
    execution_policy: ExecutionPolicy = field(default_factory=ExecutionPolicy)

    def __post_init__(self) -> None:
        if type(self.run_id) is not str or _RUN_ID.fullmatch(self.run_id) is None:
            raise CapabilityRunnerError("run ID is invalid")
        _closed_id(self.experiment_id, "experiment ID")
        if not self.tasks:
            raise CapabilityRunnerError("runner denominator is empty")
        task_ids = [task.task_id for task in self.tasks]
        if len(task_ids) != len(set(task_ids)):
            raise CapabilityRunnerError("runner task IDs are not unique")
        for label, value, maximum in (
            ("scoring seconds", self.scoring_seconds, 19_800),
            ("settlement seconds", self.settlement_seconds, 180),
            ("cleanup grace seconds", self.cleanup_grace_seconds, 190),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise CapabilityRunnerError(f"{label} is invalid")
            if not math.isfinite(float(value)) or not 0 < value <= maximum:
                raise CapabilityRunnerError(f"{label} is outside its bound")
        if self.cleanup_grace_seconds < self.settlement_seconds:
            raise CapabilityRunnerError("cleanup grace is shorter than settlement")
        experiment = EXPERIMENT_NUMERICS.get(self.experiment_id)
        if experiment is None:
            raise CapabilityRunnerError("experiment ID is not frozen")
        if float(self.scoring_seconds) != float(experiment[2]):
            raise CapabilityRunnerError("runner wall cap changed from the frozen experiment")
        if float(self.settlement_seconds) != 180.0 or float(self.cleanup_grace_seconds) != 190.0:
            raise CapabilityRunnerError("runner settlement or cleanup grace changed")
        expected_caps = UsageCaps(experiment[5], experiment[6], experiment[7])
        if self.execution_policy.usage_caps != expected_caps:
            raise CapabilityRunnerError("execution policy usage caps changed")
        allowed_routes = {
            (
                profile,
                tuple(ModelDescriptor(*MODEL_DESCRIPTOR_PAIRS[alias]) for alias in aliases),
            )
            for profile, aliases in ROUTING_CONTRACTS[self.experiment_id]
        }
        if (
            self.execution_policy.routing_profile,
            self.execution_policy.lane_descriptors,
        ) not in allowed_routes:
            raise CapabilityRunnerError("experiment routing contract changed")
        minimum, maximum, prefix, minimum_families, minimum_categories = (
            EXPERIMENT_DENOMINATOR_CONTRACTS[self.experiment_id]
        )
        difficult = [task for task in self.tasks if task.tier == "A"]
        sentinels = [task for task in self.tasks if task.tier == "sentinel"]
        if not minimum <= len(difficult) <= maximum:
            raise CapabilityRunnerError("difficult denominator changed")
        if prefix is not None and any(not task.task_id.startswith(prefix) for task in difficult):
            raise CapabilityRunnerError("difficult task namespace changed")
        if len({task.family_id for task in difficult}) < minimum_families:
            raise CapabilityRunnerError("difficult family denominator changed")
        if len({task.category for task in difficult}) < minimum_categories:
            raise CapabilityRunnerError("difficult category denominator changed")
        if maximum > 0 and {task.task_id for task in sentinels} != SENTINEL_IDS:
            raise CapabilityRunnerError("scored denominator must contain all six sentinels")
        if any(
            (task.task_id in SENTINEL_IDS) is not (task.tier == "sentinel") for task in self.tasks
        ):
            raise CapabilityRunnerError("sentinel identity/tier binding changed")
        if any(task.tier not in {"A", "sentinel"} for task in self.tasks):
            raise CapabilityRunnerError("runner denominator contains a non-scored tier")


@dataclass(frozen=True)
class RegisteredFlowFactory:
    """Closed reference to one importable worker-side flow constructor.

    ``configuration_json`` is deliberately public, canonical JSON.  Provider authentication is
    never serialized; the approved durable factory may request only the native Codex home and
    owner-only private runtime root by environment name.  Their values are copied directly into
    the disposable worker environment and never enter the request or receipt.
    """

    factory_id: str
    import_path: str
    configuration_json: str = "{}"
    provider_auth_environment: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _closed_id(self.factory_id, "flow factory ID")
        if type(self.import_path) is not str or _IMPORT_PATH.fullmatch(self.import_path) is None:
            raise CapabilityRunnerError("flow factory import path is invalid")
        if type(self.configuration_json) is not str:
            raise CapabilityRunnerError("flow factory configuration is invalid")
        encoded = self.configuration_json.encode("utf-8")
        if len(encoded) > 65_536:
            raise CapabilityRunnerError("flow factory configuration exceeds its bound")
        try:
            configuration = json.loads(self.configuration_json)
        except (json.JSONDecodeError, UnicodeError) as exc:
            raise CapabilityRunnerError("flow factory configuration is not JSON") from exc
        if not isinstance(configuration, Mapping):
            raise CapabilityRunnerError("flow factory configuration is not an object")
        canonical = json.dumps(configuration, sort_keys=True, separators=(",", ":"))
        if canonical != self.configuration_json:
            raise CapabilityRunnerError("flow factory configuration is not canonical")
        _public_scan(configuration, "flow_factory.configuration")
        if self.import_path == _DURABLE_FACTORY_PATH:
            expected = {
                "registry_id",
                "offline_profile_id",
                "catalogue_version",
                "board_implementation_version",
                "runner_image",
                "requires_provider_auth",
            }
            textual = expected - {"requires_provider_auth"}
            if (
                set(configuration) != expected
                or any(
                    type(configuration[name]) is not str or not configuration[name]
                    for name in textual
                )
                or type(configuration["requires_provider_auth"]) is not bool
            ):
                raise CapabilityRunnerError("durable flow factory configuration is invalid")
        elif self.import_path == _LOCAL_PROBE_FACTORY_PATH:
            marker = configuration.get("marker")
            if (
                set(configuration) != {"marker", "mode"}
                or configuration.get("mode")
                not in {
                    "normal",
                    "environment_probe",
                    "drive_forever",
                    "drive_ignore_sigterm",
                    "cleanup_forever",
                    "detached_setsid",
                    "loop_block_receipt",
                }
                or (
                    marker is not None
                    and (
                        type(marker) is not str
                        or re.fullmatch(r"cap05-[a-z0-9_-]{1,96}", marker) is None
                    )
                )
            ):
                raise CapabilityRunnerError("local probe flow factory configuration is invalid")
        else:
            raise CapabilityRunnerError("flow factory is not an approved flow factory")
        approved_environment = _APPROVED_FACTORY_ENVIRONMENT.get(self.import_path, frozenset())
        if (
            self.provider_auth_environment
            and self.import_path not in _APPROVED_PROVIDER_AUTH_FACTORIES
        ):
            raise CapabilityRunnerError("flow factory is not an approved provider boundary")
        if (
            type(self.provider_auth_environment) is not tuple
            or len(set(self.provider_auth_environment)) != len(self.provider_auth_environment)
            or any(name not in approved_environment for name in self.provider_auth_environment)
        ):
            raise CapabilityRunnerError("flow factory provider authentication scope is invalid")

    @classmethod
    def from_public_configuration(
        cls,
        factory_id: str,
        import_path: str,
        configuration: Mapping[str, object],
        *,
        inherit_codex_home: bool = False,
        inherit_private_runtime_root: bool = False,
    ) -> RegisteredFlowFactory:
        environment = tuple(
            name
            for name, selected in (
                ("CODEX_HOME", inherit_codex_home),
                (_PRIVATE_RUNTIME_ROOT_ENV, inherit_private_runtime_root),
                (_PRIVATE_RUNTIME_REGISTRY_DIGEST_ENV, inherit_private_runtime_root),
            )
            if selected
        )
        return cls(
            factory_id=factory_id,
            import_path=import_path,
            configuration_json=json.dumps(configuration, sort_keys=True, separators=(",", ":")),
            provider_auth_environment=environment,
        )

    def configuration(self) -> Mapping[str, object]:
        value = json.loads(self.configuration_json)
        if not isinstance(value, Mapping):  # pragma: no cover - constructor already proves this
            raise CapabilityRunnerError("flow factory configuration is not an object")
        return value


class MonotonicClock(Protocol):
    def monotonic(self) -> float: ...

    async def sleep(self, seconds: float) -> None: ...


class SystemMonotonicClock:
    def monotonic(self) -> float:
        return asyncio.get_running_loop().time()

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class RunControl:
    """Read-only deadline plus the runner-owned admission-close fence."""

    def __init__(self, start: float, scoring_deadline: float, clock: MonotonicClock) -> None:
        self.start = start
        self.scoring_deadline = scoring_deadline
        self._clock = clock
        self._admissions_closed = asyncio.Event()

    @property
    def admissions_open(self) -> bool:
        return not self._admissions_closed.is_set()

    @property
    def clock(self) -> MonotonicClock:
        return self._clock

    def offset_ms(self) -> int:
        return max(0, round((self._clock.monotonic() - self.start) * 1000))

    async def wait_for_admissions_closed(self) -> None:
        await self._admissions_closed.wait()

    def _close_admissions(self) -> None:
        self._admissions_closed.set()


class CapabilityFlow(Protocol):
    async def drive(self, control: RunControl) -> None: ...

    def snapshot(self) -> FlowEvidence: ...

    async def cleanup(self, deadline: float) -> CleanupInventory: ...


def _runtime_lanes(config: RuntimeConfig) -> tuple[ModelDescriptor, ...]:
    if config.peer_profile == "uniform_v1":
        return tuple(
            ModelDescriptor(config.model, config.reasoning_effort)
            for _ in range(config.attempts_per_challenge)
        )
    lanes: list[ModelDescriptor] = []
    for lane in range(config.attempts_per_challenge):
        if lane < config.lead_lanes:
            lanes.append(ModelDescriptor(config.model, config.reasoning_effort))
        else:
            effort = config.specialist_reasoning_efforts[
                (lane - config.lead_lanes) % len(config.specialist_reasoning_efforts)
            ]
            lanes.append(ModelDescriptor(config.specialist_model, effort))
    return tuple(lanes)


def _validate_runtime_contract(
    contract: RunnerContract,
    config: RuntimeConfig,
) -> None:
    policy = contract.execution_policy
    expected = {
        "active_challenges": policy.active_challenges,
        "concurrency": policy.lane_admissions,
        "dynamic_concurrency": policy.dynamic_leases,
        "attempts_per_challenge": policy.attempts_per_task,
        "episodes_per_challenge": policy.episodes_per_task,
        "attempt_seconds": policy.attempt_seconds,
    }
    if any(getattr(config, field, None) != value for field, value in expected.items()):
        raise CapabilityRunnerError("runtime scheduler does not match the frozen execution policy")
    if float(config.run_seconds) != float(contract.scoring_seconds):
        raise CapabilityRunnerError("runtime wall cap does not match the runner cap")
    if _runtime_lanes(config) != policy.lane_descriptors:
        raise CapabilityRunnerError("runtime roster does not match the frozen lane descriptors")
    if (
        config.board_url
        or config.board_token
        or config.team_key
        or config.watch_board
        or not config.submit_candidates
        or not config.manage_dynamic_instances
    ):
        raise CapabilityRunnerError("runtime is not a closed offline capability configuration")
    registrations = getattr(config, "task_registrations", None)
    if registrations is not None:
        runtime_identities = tuple(
            (
                item.task_id,
                item.generator_version,
                item.checker_version,
                item.service_version,
            )
            for item in registrations
        )
        frozen_identities = tuple(
            (
                task.task_id,
                task.generator_version,
                task.checker_version,
                task.service_version,
            )
            for task in contract.tasks
        )
        if runtime_identities != frozen_identities:
            raise CapabilityRunnerError("runtime task registration identity changed")


class DurableJobControlFlow:
    """Concrete additive adapter: one call to the unchanged durable solver flow."""

    def __init__(
        self,
        *,
        contract: RunnerContract,
        config: RuntimeConfig,
        board: BoardLike,
        runtime: NativeRuntime,
        evidence_source: Callable[[], FlowEvidence],
        cleanup: Callable[[float], Awaitable[CleanupInventory]],
    ) -> None:
        _validate_runtime_contract(contract, config)
        self.contract = contract
        self.config = config
        self.board = board
        self.runtime = runtime
        self.evidence_source = evidence_source
        self.cleanup_source = cleanup
        self.report: RunReport | None = None
        self._drive_started = False
        self._drive_finished = False

    async def drive(self, control: RunControl) -> None:
        if self._drive_started:
            raise CapabilityRunnerError("durable flow may be driven only once")
        self._drive_started = True
        if abs(control.scoring_deadline - control.start - float(self.config.run_seconds)) > 1e-6:
            raise CapabilityRunnerError("durable flow deadline changed")
        try:
            self.report = await DurableJobControl.drive(
                self.config,
                board=self.board,
                runtime=self.runtime,
                clock=control.clock,
                absolute_deadline=control.scoring_deadline,
            )
        finally:
            self._drive_finished = True

    def snapshot(self) -> FlowEvidence:
        if not self._drive_started:
            raise CapabilityRunnerError("durable flow was not started")
        if not self._drive_finished:
            raise CapabilityRunnerError("durable flow remains live")
        evidence = self.evidence_source()
        snapshot = getattr(self.board, "public_snapshot", None)
        if not callable(snapshot):
            raise CapabilityRunnerError("offline Board lacks checker cache attestation")
        board_attestation = CheckerEconomyAttestation.from_offline_board_snapshot(
            snapshot(), self.contract.tasks
        )
        if evidence.checker_attestation != board_attestation:
            raise CapabilityRunnerError("flow evidence contradicts the offline Board cache")
        return evidence

    async def cleanup(self, deadline: float) -> CleanupInventory:
        return await self.cleanup_source(deadline)


def durable_job_control_flow(
    *,
    contract: RunnerContract,
    config: RuntimeConfig,
    board: BoardLike,
    runtime: NativeRuntime,
    evidence_source: Callable[[], FlowEvidence],
    cleanup: Callable[[float], Awaitable[CleanupInventory]],
) -> DurableJobControlFlow:
    """Construct a validated CAP-02/DurableJobControl capability flow."""

    return DurableJobControlFlow(
        contract=contract,
        config=config,
        board=board,
        runtime=runtime,
        evidence_source=evidence_source,
        cleanup=cleanup,
    )


def _sum_usage(rows: Sequence[Usage]) -> Usage:
    def total(name: str) -> int | None:
        values = [getattr(row, name) for row in rows]
        return None if any(value is None for value in values) else sum(values)

    return Usage(*(total(name) for name in ("input", "cached_input", "output", "reasoning")))


def _interval_union(intervals: Sequence[tuple[int, int]]) -> int:
    result = 0
    end = -1
    for start, stop in sorted(intervals):
        if stop <= start:
            continue
        if start >= end:
            result += stop - start
        elif stop > end:
            result += stop - end
        end = max(end, stop)
    return result


def _max_overlap(intervals: Sequence[tuple[int, int]]) -> int:
    events = sorted(
        [event for start, stop in intervals if stop > start for event in ((start, 1), (stop, -1))],
        key=lambda event: (event[0], event[1]),
    )
    current = 0
    maximum = 0
    for _offset_ms, delta in events:
        current += delta
        maximum = max(maximum, current)
    return maximum


def _validate_execution_evidence(
    contract: RunnerContract,
    evidence: FlowEvidence,
    rows: Sequence[Mapping[str, object]],
) -> tuple[bool, bool]:
    policy = contract.execution_policy
    row_by_id = {str(row["task_id"]): row for row in rows}
    attestation = evidence.checker_attestation
    attested_by_task: dict[str, list[CheckerCandidateAttestation]] = {}
    for candidate in attestation.candidates:
        if candidate.task_id not in row_by_id:
            raise CapabilityRunnerError("checker attestation references an unregistered task")
        attested_by_task.setdefault(candidate.task_id, []).append(candidate)
    for task_id, row in row_by_id.items():
        checks = row["candidate_checks"]
        attested = attested_by_task.get(task_id, [])
        observed = [(item["ordinal"], item["result"]) for item in checks]
        expected = [(item.ordinal, item.result) for item in attested]
        if (
            observed != expected
            or row["candidate_repeat_count"] != sum(item.repeat_count for item in attested)
            or any(item.checker_version != row["checker_version"] for item in attested)
        ):
            raise CapabilityRunnerError("task checker evidence contradicts the Board cache")
    if sum(int(row["checker_call_count"]) for row in rows) != attestation.checker_call_count:
        raise CapabilityRunnerError("checker calls contradict the Board cache attestation")

    provider_intervals: list[tuple[int, int]] = []
    usage_values: dict[str, list[int | None]] = {
        "input": [],
        "output": [],
        "reasoning": [],
    }
    for row in rows:
        for attempt in row["provider_attempts"]:
            lane = attempt["lane"]
            if type(lane) is not int or not 0 <= lane < len(policy.lane_descriptors):
                raise CapabilityRunnerError("provider attempt lane is outside the frozen roster")
            descriptor = policy.lane_descriptors[lane]
            if (attempt["requested_model"], attempt["requested_effort"]) != (
                descriptor.model,
                descriptor.effort,
            ):
                raise CapabilityRunnerError("provider attempt requested a non-frozen descriptor")
            effective_pair = (attempt["effective_model"], attempt["effective_effort"])
            requested_pair = (attempt["requested_model"], attempt["requested_effort"])
            if attempt["status"] == "completed" and effective_pair != requested_pair:
                raise CapabilityRunnerError("completed provider attempt silently fell back")
            if (
                effective_pair[0] is not None
                and effective_pair != requested_pair
                and attempt["status"] != "descriptor_mismatch"
            ):
                raise CapabilityRunnerError("provider descriptor mismatch lacks a closed status")
            provider_intervals.append((attempt["started_ms"], attempt["ended_ms"]))
            for name, values in usage_values.items():
                values.append(attempt["usage"][name])
    if _max_overlap(provider_intervals) > policy.lane_admissions:
        raise CapabilityRunnerError("provider overlap exceeded the lane admission cap")
    task_intervals = [
        (int(row["started_ms"]), int(row["terminal_ms"]))
        for row in rows
        if row["started_ms"] is not None
    ]
    if _max_overlap(task_intervals) > policy.active_challenges:
        raise CapabilityRunnerError("active task overlap exceeded the frozen cap")
    service_intervals = [
        (attempt.started_ms, attempt.ended_ms) for attempt in evidence.service_attempts
    ]
    if _max_overlap(service_intervals) > policy.dynamic_leases:
        raise CapabilityRunnerError("service overlap exceeded the one-lease cap")
    service_terminal_status = {
        "service_start_failure": "start_failure",
        "service_unready": "unready",
        "service_lost": "lost",
    }
    for task_id, row in row_by_id.items():
        expected_service_status = service_terminal_status.get(str(row["terminal_label"]))
        if expected_service_status is not None and not any(
            attempt.task_id == task_id and attempt.status == expected_service_status
            for attempt in evidence.service_attempts
        ):
            raise CapabilityRunnerError("service terminal lacks matching attempt evidence")
    usage_complete = all(value is not None for values in usage_values.values() for value in values)
    usage_exceeded = any(
        sum(value for value in usage_values[name] if value is not None)
        > getattr(policy.usage_caps, name)
        for name in usage_values
    )
    return usage_complete, usage_exceeded


async def _race(task: asyncio.Task[object], deadline: float, clock: MonotonicClock) -> bool:
    remaining = max(0.0, deadline - clock.monotonic())
    timer = asyncio.create_task(clock.sleep(remaining))
    try:
        done, _pending = await asyncio.wait({task, timer}, return_when=asyncio.FIRST_COMPLETED)
        return task in done
    finally:
        if not timer.done():
            timer.cancel()
        await asyncio.gather(timer, return_exceptions=True)


def _uncancel_current() -> None:
    current = asyncio.current_task()
    if current is not None and hasattr(current, "uncancel"):
        current.uncancel()


async def _shield_reentrant(task: asyncio.Task[object]) -> tuple[object, bool]:
    """Await a cleanup/control task despite repeated outer cancellation requests."""

    interrupted = False
    while True:
        try:
            return await asyncio.shield(task), interrupted
        except asyncio.CancelledError:
            if task.done():
                if task.cancelled():
                    raise
                _uncancel_current()
                return task.result(), True
            interrupted = True
            _uncancel_current()


async def _race_reentrant(
    task: asyncio.Task[object], deadline: float, clock: MonotonicClock
) -> tuple[bool, bool]:
    waiter: asyncio.Task[object] = asyncio.create_task(_race(task, deadline, clock))
    result, interrupted = await _shield_reentrant(waiter)
    return bool(result), interrupted


def _consume_task(task: asyncio.Task[object]) -> None:
    if not task.done():
        return
    try:
        task.exception()
    except asyncio.CancelledError:
        pass


async def _cancel_and_drain(
    task: asyncio.Task[object], deadline: float, clock: MonotonicClock
) -> tuple[bool, bool]:
    if not task.done():
        task.cancel()
    interrupted = False
    finished = task.done()
    if not finished:
        finished, interrupted = await _race_reentrant(task, deadline, clock)
    if finished:
        _consume_task(task)
        return True, interrupted
    task.cancel()
    return False, interrupted


def _finalize_rows(
    contract: RunnerContract,
    evidence: FlowEvidence,
    *,
    status: str,
    cap_reached: bool,
    exact_cleanup: bool,
    admissions_closed_ms: int,
    settlement_end_ms: int,
) -> list[dict[str, object]]:
    expected = {task.task_id for task in contract.tasks}
    extras = set(evidence.tasks) - expected
    if extras:
        raise CapabilityRunnerError("flow evidence contains an unregistered task")
    rows: list[dict[str, object]] = []
    forced_terminal = (
        max(admissions_closed_ms + 1, settlement_end_ms) if cap_reached else settlement_end_ms
    )
    for registration in contract.tasks:
        observed = evidence.tasks.get(registration.task_id, TaskEvidence())
        if observed.terminal_label is None:
            if any(check.result == "correct" for check in observed.candidate_checks):
                label = "correct"
            elif cap_reached:
                if observed.started_ms is not None:
                    label = "global_cap"
                elif observed.admitted_ms is not None:
                    label = "queued_at_cap"
                else:
                    label = "unstarted_at_cap"
            else:
                label = "fixture_invalid"
            cleanup = exact_cleanup if observed.started_ms is not None else None
            observed = TaskEvidence(
                admitted_ms=observed.admitted_ms,
                started_ms=observed.started_ms,
                terminal_ms=forced_terminal,
                terminal_label=label,
                candidate_checks=observed.candidate_checks,
                candidate_repeat_count=observed.candidate_repeat_count,
                provider_attempts=observed.provider_attempts,
                tool_attempts=observed.tool_attempts,
                qualification=observed.qualification,
                qualification_ms=observed.qualification_ms,
                qualification_rejection_stage=observed.qualification_rejection_stage,
                independent_verification=observed.independent_verification,
                resources=observed.resources,
                cleanup_passed=cleanup,
            )
        rows.append(observed.public(registration))
    return rows


def _cap_snapshot(rows: Sequence[Mapping[str, object]], offset: int) -> dict[str, int]:
    active = sum(
        row["started_ms"] is not None and int(row["started_ms"]) <= offset < int(row["terminal_ms"])
        for row in rows
    )
    unstarted = sum(
        int(row["terminal_ms"]) > offset
        and (row["started_ms"] is None or int(row["started_ms"]) > offset)
        for row in rows
    )
    queued = sum(
        int(row["terminal_ms"]) > offset
        and row["admitted_ms"] is not None
        and int(row["admitted_ms"]) <= offset
        and (row["started_ms"] is None or int(row["started_ms"]) > offset)
        for row in rows
    )
    return {"active": active, "queued": queued, "unstarted": unstarted}


def _aggregate(
    rows: Sequence[Mapping[str, object]],
    *,
    early_complete: bool,
    scoring_cap_ms: int,
) -> dict[str, object]:
    difficult = [row for row in rows if row["tier"] == "A"]
    provider_attempts = [attempt for row in rows for attempt in row["provider_attempts"]]
    lane_intervals = [
        (
            min(scoring_cap_ms, int(attempt["started_ms"])),
            min(scoring_cap_ms, int(attempt["ended_ms"])),
        )
        for attempt in provider_attempts
        if int(attempt["started_ms"]) < scoring_cap_ms
    ]
    active_intervals = [
        (
            min(scoring_cap_ms, int(row["started_ms"])),
            min(scoring_cap_ms, int(row["terminal_ms"])),
        )
        for row in rows
        if row["started_ms"] is not None and int(row["started_ms"]) < scoring_cap_ms
    ]
    attempt_usage = [
        Usage(**attempt["usage"])  # type: ignore[arg-type]
        for attempt in provider_attempts
    ]
    return {
        "raw_correct_tasks": sum(row["raw_correct"] is True for row in difficult),
        "fresh_family_solves": len(
            {row["family_id"] for row in difficult if row["raw_correct"] is True}
        ),
        "qualification_projected": sum(row["qualification"] == "accepted" for row in difficult),
        "independently_checked": sum(
            row["independent_check"] in {"correct", "incorrect"} for row in difficult
        ),
        "provider_failures": sum(int(row["provider_failure_count"]) for row in rows),
        "tool_failures": sum(len(row["tool_failure_labels"]) for row in rows),
        "lane_time_ms": sum(stop - start for start, stop in lane_intervals),
        "global_active_wall_ms": _interval_union(active_intervals),
        "terminal": len(rows),
        "unstarted": sum(row["started"] is False for row in rows),
        "undersized_reservoir": early_complete,
        "usage": _sum_usage(attempt_usage).public(),
    }


def _validate_boundaries(
    rows: Sequence[Mapping[str, object]],
    services: Sequence[ServiceAttempt],
    *,
    admissions_closed_ms: int,
    settlement_end_ms: int,
    cleanup_end_ms: int,
) -> None:
    for row in rows:
        for lifecycle_field in ("admitted_ms", "started_ms"):
            value = row[lifecycle_field]
            if value is not None and int(value) > admissions_closed_ms:
                raise CapabilityRunnerError("task admitted or started after admissions closed")
        terminal_limit = (
            cleanup_end_ms if row["terminal_label"] == "cleanup_failure" else settlement_end_ms
        )
        if int(row["terminal_ms"]) > terminal_limit:
            raise CapabilityRunnerError("task terminal exceeded its phase boundary")
        qualification_ms = row["qualification_ms"]
        if qualification_ms is not None and int(qualification_ms) > settlement_end_ms:
            raise CapabilityRunnerError("qualification exceeded settlement")
        verification = row["independent_verification"]
        if isinstance(verification, Mapping) and (
            int(verification["started_ms"]) > admissions_closed_ms
            or int(verification["ended_ms"]) > settlement_end_ms
        ):
            raise CapabilityRunnerError("independent verification exceeded its boundary")
        for attempt in row["provider_attempts"]:
            if int(attempt["started_ms"]) > admissions_closed_ms:
                raise CapabilityRunnerError("provider attempt started after admissions closed")
            end_limit = (
                settlement_end_ms if attempt["status"] == "cancelled" else admissions_closed_ms
            )
            if int(attempt["ended_ms"]) > end_limit:
                raise CapabilityRunnerError("provider attempt exceeded its boundary")
        for attempt in row["tool_attempts"]:
            if int(attempt["started_ms"]) > admissions_closed_ms:
                raise CapabilityRunnerError("tool attempt started after admissions closed")
            end_limit = (
                settlement_end_ms if attempt["status"] == "cancelled" else admissions_closed_ms
            )
            if int(attempt["ended_ms"]) > end_limit:
                raise CapabilityRunnerError("tool attempt exceeded its boundary")
        for check in row["candidate_checks"]:
            if (
                int(check["candidate_returned_ms"]) > admissions_closed_ms
                or int(check["checker_started_ms"]) > admissions_closed_ms
                or int(check["checker_ended_ms"]) > settlement_end_ms
            ):
                raise CapabilityRunnerError("candidate/check exceeded its boundary")
    for service in services:
        if service.started_ms > admissions_closed_ms or (
            service.ready_ms is not None and service.ready_ms > admissions_closed_ms
        ):
            raise CapabilityRunnerError("service started or became ready after admissions closed")
        if service.ended_ms > cleanup_end_ms:
            raise CapabilityRunnerError("service cleanup exceeded the outer grace")


async def _run_completion_driven_worker(
    contract: RunnerContract,
    flow: CapabilityFlow,
    *,
    clock: MonotonicClock | None = None,
) -> dict[str, object]:
    """Worker-private lifecycle core; callers must use the disposable-process entrypoint."""

    active_clock = SystemMonotonicClock() if clock is None else clock
    start = active_clock.monotonic()
    scoring_deadline = start + float(contract.scoring_seconds)
    control = RunControl(start, scoring_deadline, active_clock)
    drive_task: asyncio.Task[object] = asyncio.create_task(flow.drive(control))
    status = "failed"
    failure_label: str | None = None
    interrupted = False
    early_complete = False
    cap_reached = False
    drive_drained = False
    try:
        drive_finished = await _race(drive_task, scoring_deadline, active_clock)
        if drive_finished and active_clock.monotonic() < scoring_deadline:
            drive_drained = True
            exception = drive_task.exception()
            if exception is None:
                status = "completed"
                early_complete = True
            else:
                status = "failed"
                failure_label = "drive_failure"
        else:
            status = "deadline"
            cap_reached = True
            control._close_admissions()
            settlement_deadline = scoring_deadline + float(contract.settlement_seconds)
            if drive_task.done() or await _race(drive_task, settlement_deadline, active_clock):
                drive_drained = True
                if not drive_task.cancelled() and drive_task.exception() is not None:
                    status = "failed"
                    failure_label = "drive_failure"
            else:
                drive_task.cancel()
    except asyncio.CancelledError:
        interrupted = True
        status = "interrupted"
        failure_label = "interrupted"
        control._close_admissions()
        drive_task.cancel()
        _uncancel_current()
    finally:
        control._close_admissions()

    admissions_closed_ms = min(
        round(contract.scoring_seconds * 1000),
        max(0, int((active_clock.monotonic() - start) * 1000)),
    )
    settlement_end_ms = max(
        admissions_closed_ms,
        max(0, int((active_clock.monotonic() - start) * 1000)),
    )
    settlement_end_ms = min(
        settlement_end_ms,
        admissions_closed_ms + round(contract.settlement_seconds * 1000),
    )
    if cap_reached:
        settlement_end_ms = max(settlement_end_ms, admissions_closed_ms + 1)
    cleanup_anchor = scoring_deadline if cap_reached else active_clock.monotonic()
    cleanup_deadline = cleanup_anchor + float(contract.cleanup_grace_seconds)
    if not drive_drained:
        drive_drained, cancelled_again = await _cancel_and_drain(
            drive_task,
            min(cleanup_deadline, active_clock.monotonic() + _CANCEL_DRAIN_SECONDS),
            active_clock,
        )
        if cancelled_again:
            interrupted = True
            status = "interrupted"
            failure_label = "interrupted"
        if not drive_drained:
            raise CapabilityRunnerError(
                "drive did not quiesce; outer supervisor escalation is required"
            )

    evidence = FlowEvidence(tasks={}, checker_attestation=CheckerEconomyAttestation.empty())
    try:
        evidence = flow.snapshot()
        if not isinstance(evidence, FlowEvidence):
            raise CapabilityRunnerError("flow snapshot has an invalid type")
        expected_task_ids = {task.task_id for task in contract.tasks}
        if set(evidence.tasks) - expected_task_ids:
            raise CapabilityRunnerError("flow evidence contains an unregistered task")
        if any(attempt.task_id not in expected_task_ids for attempt in evidence.service_attempts):
            raise CapabilityRunnerError("service evidence contains an unregistered task")
    except Exception as exc:  # noqa: BLE001 - private failures become one closed label
        evidence = FlowEvidence(tasks={}, checker_attestation=CheckerEconomyAttestation.empty())
        status = "failed"
        failure_label = "evidence_failure"
        if isinstance(exc, CapabilityRunnerError):
            failure_label = "evidence_contract_failure"

    if status == "completed" and any(
        evidence.tasks.get(task.task_id, TaskEvidence()).terminal_label is None
        for task in contract.tasks
    ):
        status = "failed"
        failure_label = "early_drain_incomplete"
        early_complete = False

    cleanup = CleanupInventory.unavailable()
    cleanup_task: asyncio.Task[object] = asyncio.create_task(flow.cleanup(cleanup_deadline))
    cleanup_finished, cancelled_again = await _race_reentrant(
        cleanup_task, cleanup_deadline, active_clock
    )
    if cancelled_again:
        interrupted = True
        status = "interrupted"
        failure_label = "interrupted"
    if cleanup_finished:
        try:
            result = cleanup_task.result()
            if not isinstance(result, CleanupInventory):
                raise CapabilityRunnerError("cleanup result has an invalid type")
            cleanup = result
        except Exception:  # noqa: BLE001 - cleanup failures become unavailable inventory
            cleanup = CleanupInventory.unavailable()
    else:
        cleanup_drained, cancelled_again = await _cancel_and_drain(
            cleanup_task,
            min(cleanup_deadline, active_clock.monotonic() + _CANCEL_DRAIN_SECONDS),
            active_clock,
        )
        if cancelled_again:
            interrupted = True
            status = "interrupted"
            failure_label = "interrupted"
        if not cleanup_drained:
            raise CapabilityRunnerError(
                "cleanup did not quiesce; outer supervisor escalation is required"
            )
    cleanup_end_ms = max(
        settlement_end_ms,
        max(0, int((active_clock.monotonic() - start) * 1000)),
    )
    cleanup_deadline_ms = max(0, int((cleanup_deadline - start) * 1000))
    cleanup_end_ms = min(cleanup_end_ms, cleanup_deadline_ms)
    if cleanup.public()["passed"] is not True:
        status = "failed" if not interrupted else status
        failure_label = cleanup.failure_label or "cleanup_failure"
    rows = _finalize_rows(
        contract,
        evidence,
        status=status,
        cap_reached=cap_reached,
        exact_cleanup=cleanup.public()["passed"] is True,
        admissions_closed_ms=admissions_closed_ms,
        settlement_end_ms=settlement_end_ms,
    )
    _validate_boundaries(
        rows,
        evidence.service_attempts,
        admissions_closed_ms=admissions_closed_ms,
        settlement_end_ms=settlement_end_ms,
        cleanup_end_ms=cleanup_end_ms,
    )
    usage_complete, usage_exceeded = _validate_execution_evidence(contract, evidence, rows)
    if usage_exceeded:
        status = "failed"
        failure_label = "usage_cap"
        early_complete = False
    elif not usage_complete and status in {"completed", "deadline"}:
        status = "inconclusive"
        failure_label = "usage_unavailable"
        early_complete = False
    cap_snapshot = _cap_snapshot(rows, admissions_closed_ms)
    scoring_cap_ms = round(contract.scoring_seconds * 1000)
    aggregate = _aggregate(
        rows,
        early_complete=early_complete,
        scoring_cap_ms=scoring_cap_ms,
    )
    receipt: dict[str, object] = {
        "schema": RUNNER_RECEIPT_SCHEMA,
        "status": status,
        "failure_label": failure_label,
        "run_id": contract.run_id,
        "experiment_id": contract.experiment_id,
        "scoring_cap_ms": scoring_cap_ms,
        "settlement_limit_ms": round(contract.settlement_seconds * 1000),
        "cleanup_grace_limit_ms": round(contract.cleanup_grace_seconds * 1000),
        "admissions_closed_ms": admissions_closed_ms,
        "settlement_end_ms": settlement_end_ms,
        "cleanup_end_ms": cleanup_end_ms,
        "task_order": [task.task_id for task in contract.tasks],
        "execution_policy": contract.execution_policy.public(),
        "tasks": rows,
        "cap_snapshot": cap_snapshot,
        "aggregate": aggregate,
        "service_attempts": [
            attempt.public(index) for index, attempt in enumerate(evidence.service_attempts, 1)
        ],
        "checker_attestation": evidence.checker_attestation.public(),
        "resources": evidence.resources.public(),
        "cleanup": cleanup.public(),
    }
    validate_runner_receipt(receipt)
    return receipt


def _public_scan(value: object, location: str = "receipt") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str) or _FORBIDDEN_PUBLIC_KEY.fullmatch(key):
                raise CapabilityRunnerError(f"forbidden public key at {location}")
            _public_scan(item, f"{location}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, item in enumerate(value):
            _public_scan(item, f"{location}[{index}]")
    elif isinstance(value, str):
        try:
            is_ip = ipaddress.ip_address(value.removeprefix("[").removesuffix("]")) is not None
        except ValueError:
            is_ip = False
        if is_ip or _FORBIDDEN_PUBLIC_VALUE.search(value):
            raise CapabilityRunnerError(f"forbidden public value at {location}")


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CapabilityRunnerError(f"{label} is not an object")
    return value


def _sequence(value: object, label: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise CapabilityRunnerError(f"{label} is not an array")
    return value


def _task_from_public(row: Mapping[str, object]) -> tuple[TaskRegistration, TaskEvidence]:
    registration = TaskRegistration(
        task_id=row["task_id"],  # type: ignore[arg-type]
        family_id=row["family_id"],  # type: ignore[arg-type]
        category=row["category"],  # type: ignore[arg-type]
        tier=row["tier"],  # type: ignore[arg-type]
        checker_version=row["checker_version"],  # type: ignore[arg-type]
        generator_version=row["generator_version"],  # type: ignore[arg-type]
        service_version=row["service_version"],  # type: ignore[arg-type]
    )
    provider_attempts: list[ProviderAttempt] = []
    for ordinal, raw in enumerate(_sequence(row["provider_attempts"], "provider attempts"), 1):
        attempt = _mapping(raw, "provider attempt")
        if attempt.get("ordinal") != ordinal:
            raise CapabilityRunnerError("provider attempt ordinal is invalid")
        usage = _mapping(attempt.get("usage"), "provider usage")
        provider_attempts.append(
            ProviderAttempt(
                lane=attempt["lane"],  # type: ignore[arg-type]
                requested_model=attempt["requested_model"],  # type: ignore[arg-type]
                requested_effort=attempt["requested_effort"],  # type: ignore[arg-type]
                effective_model=attempt["effective_model"],  # type: ignore[arg-type]
                effective_effort=attempt["effective_effort"],  # type: ignore[arg-type]
                effective_revision_build=attempt["effective_revision_build"],  # type: ignore[arg-type]
                native_client_version=attempt["native_client_version"],  # type: ignore[arg-type]
                status=attempt["status"],  # type: ignore[arg-type]
                started_ms=attempt["started_ms"],  # type: ignore[arg-type]
                ended_ms=attempt["ended_ms"],  # type: ignore[arg-type]
                usage=Usage(**usage),  # type: ignore[arg-type]
            )
        )
        if provider_attempts[-1].public(ordinal) != attempt:
            raise CapabilityRunnerError("provider attempt fields are not exact")
    candidate_checks: list[CandidateCheck] = []
    for ordinal, raw in enumerate(_sequence(row["candidate_checks"], "candidate checks"), 1):
        check = _mapping(raw, "candidate check")
        if check.get("ordinal") != ordinal:
            raise CapabilityRunnerError("candidate check ordinal is invalid")
        candidate_checks.append(
            CandidateCheck(
                candidate_returned_ms=check["candidate_returned_ms"],  # type: ignore[arg-type]
                checker_started_ms=check["checker_started_ms"],  # type: ignore[arg-type]
                checker_ended_ms=check["checker_ended_ms"],  # type: ignore[arg-type]
                result=check["result"],  # type: ignore[arg-type]
            )
        )
        if candidate_checks[-1].public(ordinal) != check:
            raise CapabilityRunnerError("candidate check fields are not exact")
    tool_attempts: list[ToolAttempt] = []
    for ordinal, raw in enumerate(_sequence(row["tool_attempts"], "tool attempts"), 1):
        attempt = _mapping(raw, "tool attempt")
        if attempt.get("ordinal") != ordinal:
            raise CapabilityRunnerError("tool attempt ordinal is invalid")
        tool_attempts.append(
            ToolAttempt(
                status=attempt["status"],  # type: ignore[arg-type]
                started_ms=attempt["started_ms"],  # type: ignore[arg-type]
                ended_ms=attempt["ended_ms"],  # type: ignore[arg-type]
                failure_label=attempt["failure_label"],  # type: ignore[arg-type]
            )
        )
        if tool_attempts[-1].public(ordinal) != attempt:
            raise CapabilityRunnerError("tool attempt fields are not exact")
    raw_verification = row["independent_verification"]
    verification = None
    if raw_verification is not None:
        values = _mapping(raw_verification, "independent verification")
        verification = IndependentVerification(
            started_ms=values["started_ms"],  # type: ignore[arg-type]
            ended_ms=values["ended_ms"],  # type: ignore[arg-type]
            result=values["result"],  # type: ignore[arg-type]
            method_version=values["method_version"],  # type: ignore[arg-type]
        )
        if verification.public() != values:
            raise CapabilityRunnerError("independent verification fields are not exact")
    resources = _mapping(row["resources"], "task resources")
    resource = ResourceObservation(**resources)  # type: ignore[arg-type]
    evidence = TaskEvidence(
        admitted_ms=row["admitted_ms"],  # type: ignore[arg-type]
        started_ms=row["started_ms"],  # type: ignore[arg-type]
        terminal_ms=row["terminal_ms"],  # type: ignore[arg-type]
        terminal_label=row["terminal_label"],  # type: ignore[arg-type]
        candidate_checks=tuple(candidate_checks),
        candidate_repeat_count=row["candidate_repeat_count"],  # type: ignore[arg-type]
        provider_attempts=tuple(provider_attempts),
        tool_attempts=tuple(tool_attempts),
        qualification=row["qualification"],  # type: ignore[arg-type]
        qualification_ms=row["qualification_ms"],  # type: ignore[arg-type]
        qualification_rejection_stage=row["qualification_rejection_stage"],  # type: ignore[arg-type]
        independent_verification=verification,
        resources=resource,
        cleanup_passed=row["cleanup_passed"],  # type: ignore[arg-type]
    )
    if evidence.public(registration) != row:
        raise CapabilityRunnerError("task row fields or aggregates are not exact")
    return registration, evidence


def validate_runner_receipt(receipt: Mapping[str, object]) -> None:
    """Deeply validate the closed runner receipt and all recomputable cross-fields."""

    expected = {
        "schema",
        "status",
        "failure_label",
        "run_id",
        "experiment_id",
        "scoring_cap_ms",
        "settlement_limit_ms",
        "cleanup_grace_limit_ms",
        "admissions_closed_ms",
        "settlement_end_ms",
        "cleanup_end_ms",
        "task_order",
        "execution_policy",
        "tasks",
        "cap_snapshot",
        "aggregate",
        "service_attempts",
        "checker_attestation",
        "resources",
        "cleanup",
    }
    if set(receipt) != expected or receipt.get("schema") != RUNNER_RECEIPT_SCHEMA:
        raise CapabilityRunnerError("runner receipt shape is invalid")
    _public_scan(receipt)
    status = receipt.get("status")
    if status not in {"completed", "deadline", "failed", "interrupted", "inconclusive"}:
        raise CapabilityRunnerError("runner receipt status is invalid")
    failure_label = receipt.get("failure_label")
    if (status in {"completed", "deadline"}) is not (failure_label is None):
        raise CapabilityRunnerError("runner status/failure label mismatch")
    if failure_label is not None:
        _closed_id(failure_label, "runner failure label")
    task_order = _sequence(receipt.get("task_order"), "task order")
    raw_rows = _sequence(receipt.get("tasks"), "tasks")
    rows = [_mapping(row, "task row") for row in raw_rows]
    parsed = [_task_from_public(row) for row in rows]
    registrations = tuple(item[0] for item in parsed)
    task_evidence = {item[0].task_id: item[1] for item in parsed}
    row_ids = [item.task_id for item in registrations]
    if row_ids != list(task_order) or len(row_ids) != len(set(row_ids)):
        raise CapabilityRunnerError("runner receipt dropped or reordered task rows")

    for name in (
        "scoring_cap_ms",
        "settlement_limit_ms",
        "cleanup_grace_limit_ms",
        "admissions_closed_ms",
        "settlement_end_ms",
        "cleanup_end_ms",
    ):
        value = receipt.get(name)
        if type(value) is not int or value < 0:
            raise CapabilityRunnerError("runner receipt timing is invalid")
    scoring_cap_ms = int(receipt["scoring_cap_ms"])
    settlement_limit_ms = int(receipt["settlement_limit_ms"])
    cleanup_grace_limit_ms = int(receipt["cleanup_grace_limit_ms"])
    admissions_closed_ms = int(receipt["admissions_closed_ms"])
    settlement_end_ms = int(receipt["settlement_end_ms"])
    cleanup_end_ms = int(receipt["cleanup_end_ms"])
    if not (
        admissions_closed_ms <= scoring_cap_ms
        and admissions_closed_ms <= settlement_end_ms <= cleanup_end_ms
        and settlement_end_ms <= admissions_closed_ms + settlement_limit_ms
    ):
        raise CapabilityRunnerError("runner receipt phases are out of order or unbounded")
    cleanup_anchor_ms = (
        scoring_cap_ms if admissions_closed_ms == scoring_cap_ms else settlement_end_ms
    )
    if cleanup_end_ms > cleanup_anchor_ms + cleanup_grace_limit_ms:
        raise CapabilityRunnerError("runner cleanup exceeded its anchored grace")

    policy_row = _mapping(receipt["execution_policy"], "execution policy")
    if (
        set(policy_row)
        != {
            "routing_profile",
            "lane_descriptors",
            "active_challenges",
            "lane_admissions",
            "dynamic_leases",
            "attempts_per_task",
            "episodes_per_task",
            "attempt_seconds",
            "usage_caps",
            "fallback_allowed",
        }
        or policy_row["fallback_allowed"] is not False
    ):
        raise CapabilityRunnerError("execution policy fields are invalid")
    descriptors = tuple(
        ModelDescriptor(**_mapping(row, "lane descriptor"))  # type: ignore[arg-type]
        for row in _sequence(policy_row["lane_descriptors"], "lane descriptors")
    )
    caps = UsageCaps(**_mapping(policy_row["usage_caps"], "usage caps"))  # type: ignore[arg-type]
    policy = ExecutionPolicy(
        routing_profile=policy_row["routing_profile"],  # type: ignore[arg-type]
        lane_descriptors=descriptors,
        active_challenges=policy_row["active_challenges"],  # type: ignore[arg-type]
        lane_admissions=policy_row["lane_admissions"],  # type: ignore[arg-type]
        dynamic_leases=policy_row["dynamic_leases"],  # type: ignore[arg-type]
        attempts_per_task=policy_row["attempts_per_task"],  # type: ignore[arg-type]
        episodes_per_task=policy_row["episodes_per_task"],  # type: ignore[arg-type]
        attempt_seconds=policy_row["attempt_seconds"],  # type: ignore[arg-type]
        usage_caps=caps,
    )
    if policy.public() != policy_row:
        raise CapabilityRunnerError("execution policy is not canonical")

    raw_attestation = _mapping(receipt["checker_attestation"], "checker attestation")
    if set(raw_attestation) != {
        "source",
        "cache_scope",
        "unique_candidate_count",
        "repeat_candidate_count",
        "checker_call_count",
        "candidates",
    }:
        raise CapabilityRunnerError("checker attestation fields are invalid")
    candidates = tuple(
        CheckerCandidateAttestation(**_mapping(row, "attested candidate"))  # type: ignore[arg-type]
        for row in _sequence(raw_attestation["candidates"], "attested candidates")
    )
    attestation = CheckerEconomyAttestation(
        source=raw_attestation["source"],  # type: ignore[arg-type]
        cache_scope=raw_attestation["cache_scope"],  # type: ignore[arg-type]
        unique_candidate_count=raw_attestation["unique_candidate_count"],  # type: ignore[arg-type]
        repeat_candidate_count=raw_attestation["repeat_candidate_count"],  # type: ignore[arg-type]
        checker_call_count=raw_attestation["checker_call_count"],  # type: ignore[arg-type]
        candidates=candidates,
    )
    if attestation.public() != raw_attestation:
        raise CapabilityRunnerError("checker attestation is not canonical")

    services: list[ServiceAttempt] = []
    for ordinal, raw in enumerate(_sequence(receipt["service_attempts"], "services"), 1):
        row = _mapping(raw, "service")
        if row.get("ordinal") != ordinal:
            raise CapabilityRunnerError("service ordinal is invalid")
        services.append(
            ServiceAttempt(
                service_id=f"private-service-{ordinal}",
                task_id=row["task_id"],  # type: ignore[arg-type]
                status=row["status"],  # type: ignore[arg-type]
                started_ms=row["started_ms"],  # type: ignore[arg-type]
                ready_ms=row["ready_ms"],  # type: ignore[arg-type]
                ended_ms=row["ended_ms"],  # type: ignore[arg-type]
                failure_label=row["failure_label"],  # type: ignore[arg-type]
            )
        )
        if services[-1].public(ordinal) != row:
            raise CapabilityRunnerError("service fields are not exact")
    resources_row = _mapping(receipt["resources"], "resources")
    resources = ResourceObservation(**resources_row)  # type: ignore[arg-type]
    if resources.public() != resources_row:
        raise CapabilityRunnerError("resource fields are not exact")
    contract = RunnerContract(
        run_id=receipt["run_id"],  # type: ignore[arg-type]
        experiment_id=receipt["experiment_id"],  # type: ignore[arg-type]
        tasks=registrations,
        scoring_seconds=scoring_cap_ms / 1000,
        settlement_seconds=settlement_limit_ms / 1000,
        cleanup_grace_seconds=cleanup_grace_limit_ms / 1000,
        execution_policy=policy,
    )
    evidence = FlowEvidence(
        tasks=task_evidence,
        checker_attestation=attestation,
        service_attempts=tuple(services),
        resources=resources,
    )
    usage_complete, usage_exceeded = _validate_execution_evidence(contract, evidence, rows)
    _validate_boundaries(
        rows,
        services,
        admissions_closed_ms=admissions_closed_ms,
        settlement_end_ms=settlement_end_ms,
        cleanup_end_ms=cleanup_end_ms,
    )
    if usage_exceeded and failure_label != "usage_cap":
        raise CapabilityRunnerError("usage cap result is inconsistent")
    if not usage_exceeded and failure_label == "usage_cap":
        raise CapabilityRunnerError("usage cap label lacks a known over-cap lower bound")
    if not usage_complete and status in {"completed", "deadline"}:
        raise CapabilityRunnerError("successful receipt contains unavailable usage")
    if status == "inconclusive" and (usage_complete or failure_label != "usage_unavailable"):
        raise CapabilityRunnerError("runner inconclusive status lacks null usage evidence")
    if failure_label == "usage_unavailable" and (usage_complete or status != "inconclusive"):
        raise CapabilityRunnerError("usage-unavailable label/status mismatch")

    expected_snapshot = _cap_snapshot(rows, admissions_closed_ms)
    if receipt["cap_snapshot"] != expected_snapshot:
        raise CapabilityRunnerError("cap snapshot contradicts task lifecycles")
    aggregate = _mapping(receipt["aggregate"], "aggregate")
    expected_aggregate = _aggregate(
        rows,
        early_complete=aggregate.get("undersized_reservoir") is True,
        scoring_cap_ms=scoring_cap_ms,
    )
    if aggregate != expected_aggregate:
        raise CapabilityRunnerError("aggregate contradicts task evidence")
    if int(aggregate["global_active_wall_ms"]) > scoring_cap_ms:
        raise CapabilityRunnerError("scored active wall exceeds the scoring cap")
    if int(aggregate["lane_time_ms"]) > policy.lane_admissions * scoring_cap_ms:
        raise CapabilityRunnerError("scored lane time exceeds the lane-time cap")

    cleanup_row = _mapping(receipt["cleanup"], "cleanup")
    cleanup_fields = {
        "passed",
        "failure_label",
        "inventory_complete",
        "owned_processes_remaining",
        "owned_containers_remaining",
        "owned_volumes_remaining",
        "owned_networks_remaining",
        "owned_services_remaining",
        "owned_workspaces_remaining",
        "owned_state_objects_remaining",
        "owned_run_ids_remaining",
    }
    if set(cleanup_row) != cleanup_fields:
        raise CapabilityRunnerError("cleanup fields are invalid")
    cleanup = CleanupInventory(
        cleanup_row["owned_processes_remaining"],  # type: ignore[arg-type]
        cleanup_row["owned_containers_remaining"],  # type: ignore[arg-type]
        cleanup_row["owned_volumes_remaining"],  # type: ignore[arg-type]
        cleanup_row["owned_networks_remaining"],  # type: ignore[arg-type]
        cleanup_row["owned_services_remaining"],  # type: ignore[arg-type]
        cleanup_row["owned_workspaces_remaining"],  # type: ignore[arg-type]
        cleanup_row["owned_state_objects_remaining"],  # type: ignore[arg-type]
        cleanup_row["owned_run_ids_remaining"],  # type: ignore[arg-type]
        failure_label=cleanup_row["failure_label"],  # type: ignore[arg-type]
    )
    if cleanup.public() != cleanup_row:
        raise CapabilityRunnerError("cleanup inventory is not canonical")
    if status in {"completed", "deadline", "inconclusive"} and cleanup_row["passed"] is not True:
        raise CapabilityRunnerError("terminal runner status lacks exact cleanup")


def _contract_public(contract: RunnerContract) -> dict[str, object]:
    return {
        "schema": "rapido-offline-capability-runner-contract-v1",
        "run_id": contract.run_id,
        "experiment_id": contract.experiment_id,
        "scoring_seconds": contract.scoring_seconds,
        "settlement_seconds": contract.settlement_seconds,
        "cleanup_grace_seconds": contract.cleanup_grace_seconds,
        "execution_policy": contract.execution_policy.public(),
        "tasks": [
            {
                "task_id": task.task_id,
                "family_id": task.family_id,
                "category": task.category,
                "tier": task.tier,
                "checker_version": task.checker_version,
                "generator_version": task.generator_version,
                "service_version": task.service_version,
            }
            for task in contract.tasks
        ],
    }


def _contract_from_public(raw: object) -> RunnerContract:
    row = _mapping(raw, "serialized runner contract")
    if (
        set(row)
        != {
            "schema",
            "run_id",
            "experiment_id",
            "scoring_seconds",
            "settlement_seconds",
            "cleanup_grace_seconds",
            "execution_policy",
            "tasks",
        }
        or row["schema"] != "rapido-offline-capability-runner-contract-v1"
    ):
        raise CapabilityRunnerError("serialized runner contract fields are invalid")
    policy_row = _mapping(row["execution_policy"], "serialized execution policy")
    if (
        set(policy_row)
        != {
            "routing_profile",
            "lane_descriptors",
            "active_challenges",
            "lane_admissions",
            "dynamic_leases",
            "attempts_per_task",
            "episodes_per_task",
            "attempt_seconds",
            "usage_caps",
            "fallback_allowed",
        }
        or policy_row["fallback_allowed"] is not False
    ):
        raise CapabilityRunnerError("serialized execution policy fields are invalid")
    descriptors = tuple(
        ModelDescriptor(**_mapping(value, "serialized lane descriptor"))  # type: ignore[arg-type]
        for value in _sequence(policy_row["lane_descriptors"], "serialized lane descriptors")
    )
    policy = ExecutionPolicy(
        routing_profile=policy_row["routing_profile"],  # type: ignore[arg-type]
        lane_descriptors=descriptors,
        active_challenges=policy_row["active_challenges"],  # type: ignore[arg-type]
        lane_admissions=policy_row["lane_admissions"],  # type: ignore[arg-type]
        dynamic_leases=policy_row["dynamic_leases"],  # type: ignore[arg-type]
        attempts_per_task=policy_row["attempts_per_task"],  # type: ignore[arg-type]
        episodes_per_task=policy_row["episodes_per_task"],  # type: ignore[arg-type]
        attempt_seconds=policy_row["attempt_seconds"],  # type: ignore[arg-type]
        usage_caps=UsageCaps(
            **_mapping(policy_row["usage_caps"], "serialized usage caps")  # type: ignore[arg-type]
        ),
    )
    if policy.public() != policy_row:
        raise CapabilityRunnerError("serialized execution policy is not canonical")
    tasks: list[TaskRegistration] = []
    task_fields = {
        "task_id",
        "family_id",
        "category",
        "tier",
        "checker_version",
        "generator_version",
        "service_version",
    }
    for value in _sequence(row["tasks"], "serialized tasks"):
        task_row = _mapping(value, "serialized task")
        if set(task_row) != task_fields:
            raise CapabilityRunnerError("serialized task fields are invalid")
        tasks.append(TaskRegistration(**task_row))  # type: ignore[arg-type]
    contract = RunnerContract(
        run_id=row["run_id"],  # type: ignore[arg-type]
        experiment_id=row["experiment_id"],  # type: ignore[arg-type]
        tasks=tuple(tasks),
        scoring_seconds=row["scoring_seconds"],  # type: ignore[arg-type]
        settlement_seconds=row["settlement_seconds"],  # type: ignore[arg-type]
        cleanup_grace_seconds=row["cleanup_grace_seconds"],  # type: ignore[arg-type]
        execution_policy=policy,
    )
    if _contract_public(contract) != row:
        raise CapabilityRunnerError("serialized runner contract is not canonical")
    return contract


def _factory_public(factory: RegisteredFlowFactory) -> dict[str, object]:
    return {
        "factory_id": factory.factory_id,
        "import_path": factory.import_path,
        "configuration_json": factory.configuration_json,
        "provider_auth_environment": list(factory.provider_auth_environment),
    }


def _factory_from_public(raw: object) -> RegisteredFlowFactory:
    row = _mapping(raw, "serialized flow factory")
    if set(row) != {
        "factory_id",
        "import_path",
        "configuration_json",
        "provider_auth_environment",
    }:
        raise CapabilityRunnerError("serialized flow factory fields are invalid")
    environment = _sequence(
        row["provider_auth_environment"], "serialized provider authentication environment"
    )
    factory = RegisteredFlowFactory(
        factory_id=row["factory_id"],  # type: ignore[arg-type]
        import_path=row["import_path"],  # type: ignore[arg-type]
        configuration_json=row["configuration_json"],  # type: ignore[arg-type]
        provider_auth_environment=tuple(environment),  # type: ignore[arg-type]
    )
    if _factory_public(factory) != row:
        raise CapabilityRunnerError("serialized flow factory is not canonical")
    return factory


def _resolve_flow_factory(factory: RegisteredFlowFactory) -> Callable[..., object]:
    module_name, qualified_name = factory.import_path.split(":", 1)
    module = importlib.import_module(module_name)
    value: object = module
    for component in qualified_name.split("."):
        value = getattr(value, component)
    if not callable(value):
        raise CapabilityRunnerError("registered flow factory is not callable")
    if (
        getattr(value, "__module__", None) != module_name
        or getattr(value, "__qualname__", None) != qualified_name
    ):
        raise CapabilityRunnerError("registered flow factory identity changed")
    try:
        restored = pickle.loads(pickle.dumps(value))
    except Exception as exc:
        raise CapabilityRunnerError("registered flow factory is not picklable") from exc
    if (
        getattr(restored, "__module__", None) != module_name
        or getattr(restored, "__qualname__", None) != qualified_name
    ):
        raise CapabilityRunnerError("registered flow factory pickle identity changed")
    return value


def _receipt_matches_contract(receipt: Mapping[str, object], contract: RunnerContract) -> bool:
    if (
        receipt.get("run_id") != contract.run_id
        or receipt.get("experiment_id") != contract.experiment_id
        or receipt.get("scoring_cap_ms") != round(contract.scoring_seconds * 1000)
        or receipt.get("settlement_limit_ms") != round(contract.settlement_seconds * 1000)
        or receipt.get("cleanup_grace_limit_ms") != round(contract.cleanup_grace_seconds * 1000)
        or receipt.get("execution_policy") != contract.execution_policy.public()
    ):
        return False
    rows = receipt.get("tasks")
    if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes, bytearray)):
        return False
    observed = [
        tuple(
            row.get(name)
            for name in (
                "task_id",
                "family_id",
                "category",
                "tier",
                "checker_version",
                "generator_version",
                "service_version",
            )
        )
        for row in rows
        if isinstance(row, Mapping)
    ]
    expected = [
        (
            task.task_id,
            task.family_id,
            task.category,
            task.tier,
            task.checker_version,
            task.generator_version,
            task.service_version,
        )
        for task in contract.tasks
    ]
    return observed == expected


def _write_all(descriptor: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _worker_response(descriptor: int, message: Mapping[str, object]) -> None:
    encoded = json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > _MAX_SUPERVISOR_RESPONSE_BYTES:
        encoded = json.dumps(
            {
                "schema": SUPERVISOR_MESSAGE_SCHEMA,
                "kind": "error",
                "failure_label": "worker_response_oversize",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    _write_all(descriptor, len(encoded).to_bytes(4, "big") + encoded)


def _subprocess_worker_main(result_descriptor: int) -> None:
    """Read one public request and hard-exit after one bounded public response."""

    response: Mapping[str, object] = {
        "schema": SUPERVISOR_MESSAGE_SCHEMA,
        "kind": "error",
        "failure_label": "worker_failure",
    }
    exit_code = 2
    loop: asyncio.AbstractEventLoop | None = None
    try:
        request_bytes = sys.stdin.buffer.read(_MAX_SUPERVISOR_REQUEST_BYTES + 1)
        if len(request_bytes) > _MAX_SUPERVISOR_REQUEST_BYTES:
            raise CapabilityRunnerError("supervisor request exceeds its bound")
        request = json.loads(request_bytes)
        request_row = _mapping(request, "supervisor request")
        if set(request_row) != {"schema", "contract", "factory"} or request_row["schema"] != (
            "rapido-offline-capability-supervisor-request-v1"
        ):
            raise CapabilityRunnerError("supervisor request fields are invalid")
        _public_scan(request_row, "supervisor_request")
        contract = _contract_from_public(request_row["contract"])
        factory_registration = _factory_from_public(request_row["factory"])
        factory = _resolve_flow_factory(factory_registration)
        flow = factory(contract, factory_registration.configuration())
        if any(
            not callable(getattr(flow, name, None)) for name in ("drive", "snapshot", "cleanup")
        ):
            raise CapabilityRunnerError("registered flow factory returned an invalid flow")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        _worker_response(
            result_descriptor,
            {"schema": SUPERVISOR_MESSAGE_SCHEMA, "kind": "ready"},
        )
        receipt = loop.run_until_complete(_run_completion_driven_worker(contract, flow))
        validate_runner_receipt(receipt)
        if not _receipt_matches_contract(receipt, contract):
            raise CapabilityRunnerError("worker receipt changed the serialized contract")
        _public_scan(receipt)
        response = {
            "schema": SUPERVISOR_MESSAGE_SCHEMA,
            "kind": "receipt",
            "receipt": receipt,
        }
        exit_code = 0
    except BaseException as exc:  # noqa: BLE001 - only a closed label leaves the worker
        label = (
            "worker_nonquiescent"
            if isinstance(exc, CapabilityRunnerError) and "outer supervisor escalation" in str(exc)
            else "worker_failure"
        )
        response = {
            "schema": SUPERVISOR_MESSAGE_SCHEMA,
            "kind": "error",
            "failure_label": label,
        }
    try:
        _worker_response(result_descriptor, response)
    finally:
        try:
            os.close(result_descriptor)
        finally:
            # Never ask asyncio to cooperatively close cancellation-resistant tasks here.  The
            # disposable process is the escalation boundary and discards its entire event loop.
            os._exit(exit_code)


def _linux_child_adoption_state() -> bool:
    if os.getpid() == 1:
        return True
    value = ctypes.c_int()
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(37, ctypes.byref(value), 0, 0, 0) != 0:  # PR_GET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "cannot inspect capability child adoption")
    return value.value == 1


def _enable_linux_child_adoption() -> bool:
    """Make this dedicated containment process the adoption point for its whole tree."""

    if not sys.platform.startswith("linux"):
        raise CapabilityRunnerError("Linux descendant containment is unavailable")
    previous = _linux_child_adoption_state()
    if os.getpid() == 1:
        return previous
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "cannot adopt capability worker descendants")
    return previous


def _restore_linux_child_adoption(previous: bool) -> None:
    if os.getpid() == 1 or previous:
        return
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(36, 0, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "cannot restore capability child adoption")


def _linux_children_of(process: int) -> set[int]:
    """Enumerate kernel parentage, unioning children created by every thread."""

    task_root = f"/proc/{process}/task"
    try:
        task_names = os.listdir(task_root)
    except FileNotFoundError:
        if process == os.getpid():
            raise CapabilityRunnerError("cannot enumerate contained descendants") from None
        return set()
    except OSError:
        raise CapabilityRunnerError("cannot enumerate contained descendants") from None
    children: set[int] = set()
    for task_name in task_names:
        try:
            with open(f"{task_root}/{task_name}/children", encoding="ascii") as source:
                raw = source.read()
        except FileNotFoundError:
            continue
        except (OSError, UnicodeError):
            raise CapabilityRunnerError("cannot enumerate contained descendants") from None
        for child_text in raw.split():
            try:
                child = int(child_text)
            except ValueError:
                raise CapabilityRunnerError("contained descendant identity is invalid") from None
            if child <= 0:
                raise CapabilityRunnerError("contained descendant identity is invalid")
            children.add(child)
    return children


def _linux_owned_descendants() -> set[int]:
    pending = [os.getpid()]
    descendants: set[int] = set()
    while pending:
        for child in _linux_children_of(pending.pop()):
            if child not in descendants:
                descendants.add(child)
                pending.append(child)
    return descendants


def _signal_exact_processes(processes: set[int], sent_signal: int) -> None:
    """Signal only still-live identities opened through Linux pidfds."""

    for process in sorted(processes):
        try:
            descriptor = os.pidfd_open(process)
        except ProcessLookupError:
            continue
        try:
            signal.pidfd_send_signal(descriptor, sent_signal)
        except ProcessLookupError:
            pass
        finally:
            os.close(descriptor)


def _reap_contained_children() -> dict[int, int]:
    statuses: dict[int, int] = {}
    while True:
        try:
            child, status = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return statuses
        except InterruptedError:
            continue
        if child == 0:
            return statuses
        statuses[child] = status


def _reap_linux_parent_boundary() -> tuple[bool, bool]:
    """Empty the caller's dedicated adopted-child set without PID/PGID reuse."""

    term_started = time.monotonic()
    kill_started: float | None = None
    used_kill = False
    while True:
        _reap_contained_children()
        descendants = _linux_owned_descendants()
        if not descendants:
            _reap_contained_children()
            if not _linux_owned_descendants():
                return used_kill, True
        now = time.monotonic()
        if now - term_started < 0.05:
            _signal_exact_processes(descendants, signal.SIGTERM)
        else:
            used_kill = True
            if kill_started is None:
                kill_started = now
            _signal_exact_processes(descendants, signal.SIGKILL)
        if kill_started is not None and now - kill_started >= 0.5:
            return used_kill, False
        time.sleep(0.002)


def _linux_containment_main(result_descriptor: int, proof_descriptor: int) -> None:
    """Own one worker tree until every session-escaping descendant is killed and reaped."""

    try:
        _enable_linux_child_adoption()
        stop_requested = False

        def request_stop(_signum: int, _frame: object) -> None:
            nonlocal stop_requested
            stop_requested = True

        signal.signal(signal.SIGTERM, request_stop)
        signal.signal(signal.SIGINT, request_stop)
        worker_pid = os.fork()
        if worker_pid == 0:
            os.close(proof_descriptor)
            signal.signal(signal.SIGTERM, signal.SIG_DFL)
            signal.signal(signal.SIGINT, signal.SIG_DFL)
            _subprocess_worker_main(result_descriptor)
        os.close(result_descriptor)

        worker_status: int | None = None
        term_started: float | None = None
        kill_started: float | None = None
        used_kill = False
        while True:
            reaped = _reap_contained_children()
            if worker_pid in reaped:
                worker_status = reaped[worker_pid]
            descendants = _linux_owned_descendants()
            if worker_status is not None and not descendants:
                break
            now = time.monotonic()
            if (stop_requested or worker_status is not None) and descendants:
                if term_started is None:
                    term_started = now
                if now - term_started < 0.05:
                    _signal_exact_processes(descendants, signal.SIGTERM)
                else:
                    if kill_started is None:
                        kill_started = now
                    used_kill = True
                    _signal_exact_processes(descendants, signal.SIGKILL)
            if kill_started is not None and now - kill_started >= 0.15:
                # SIGKILL cannot be resisted.  Remaining identities are unreaped, never absent.
                os._exit(246)
            time.sleep(0.002)

        _write_all(proof_descriptor, b"1")
        os.close(proof_descriptor)
        if used_kill:
            os._exit(_CONTAINMENT_KILLED_EXIT)
        if worker_status is None:
            os._exit(246)
        exit_code = os.waitstatus_to_exitcode(worker_status)
        os._exit(exit_code if exit_code >= 0 else 128 - exit_code)
    except BaseException:  # noqa: BLE001 - containment must fail closed before hard exit
        try:
            os.close(proof_descriptor)
        except OSError:
            pass
        try:
            os.close(result_descriptor)
        except OSError:
            pass
        os._exit(246)


def _worker_environment(factory: RegisteredFlowFactory) -> dict[str, str]:
    allowed = (
        "PATH",
        "PYTHONPATH",
        "VIRTUAL_ENV",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TMPDIR",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    )
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    for name in factory.provider_auth_environment:
        value = os.environ.get(name)
        if value is None:
            raise CapabilityRunnerError("approved provider authentication environment is absent")
        environment[name] = value
    return environment


def _process_group_exists(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    return True


def _signal_process_group(process: subprocess.Popen[bytes], sent_signal: int) -> None:
    try:
        os.killpg(process.pid, sent_signal)
    except ProcessLookupError:
        pass


def _terminate_and_reap(
    process: subprocess.Popen[bytes],
    *,
    linux_containment: bool,
    linux_parent_boundary: bool = False,
    proof_descriptor: int = -1,
) -> tuple[bool, bool, bool, bool]:
    terminated = False
    killed = False
    group_id = process.pid
    exit_deadline = time.monotonic() + _SUPERVISOR_EXIT_SECONDS
    while process.poll() is None and time.monotonic() < exit_deadline:
        time.sleep(0.005)
    if process.poll() is None or (not linux_containment and _process_group_exists(group_id)):
        terminated = True
        _signal_process_group(process, signal.SIGTERM)
        deadline = time.monotonic() + _SUPERVISOR_TERM_SECONDS
        while time.monotonic() < deadline and (
            process.poll() is None or (not linux_containment and _process_group_exists(group_id))
        ):
            time.sleep(0.005)
    if process.poll() is None or (not linux_containment and _process_group_exists(group_id)):
        killed = True
        _signal_process_group(process, signal.SIGKILL)
    # SIGKILL is the final production boundary: waitpid must reap the exact direct child before
    # any receipt or error can escape.  Descendants share the new process group and receive it too.
    if process.poll() is None:
        process.wait()
    else:
        process.wait(timeout=0)
    child_reaped = process.returncode is not None
    # ``killed`` records a SIGKILL sent by this supervisor, not an outer actor's exit status.
    # Treating an externally SIGKILLed wrapper as our kill would overclaim containment evidence.
    killed = killed or process.returncode == _CONTAINMENT_KILLED_EXIT
    if linux_containment:
        # The trusted wrapper writes this proof only after its subreaper has reaped every exact
        # descendant.  An outer SIGKILL or wrapper failure closes the pipe without proof.  No
        # PGID/PID lookup occurs after waitpid, so reuse cannot create an absence claim.
        proof = b""
        if proof_descriptor >= 0:
            try:
                proof = os.read(proof_descriptor, 2)
            except BlockingIOError:
                pass
        if linux_parent_boundary:
            adopted_killed, adopted_absent = _reap_linux_parent_boundary()
            killed = killed or adopted_killed
            child_absent = child_reaped and adopted_absent
        else:
            child_absent = child_reaped and proof == b"1"
    else:
        deadline = time.monotonic() + 1.0
        while _process_group_exists(group_id) and time.monotonic() < deadline:
            _signal_process_group(process, signal.SIGKILL)
            time.sleep(0.005)
        child_absent = child_reaped and not _process_group_exists(group_id)
    return terminated, killed, child_reaped, child_absent


def _closed_supervisor_error(
    label: str,
    process_evidence: tuple[bool, bool, bool, bool],
) -> CapabilitySupervisorError:
    terminated, killed, child_reaped, child_absent = process_evidence
    if not child_absent:
        # Returning while the group is live is forbidden.  A second exact hard-kill is preferable
        # to inventing an absence receipt.
        raise RuntimeError("capability worker process group could not be proven absent")
    return CapabilitySupervisorError(
        label,
        terminated=terminated,
        killed=killed,
        child_reaped=child_reaped,
        child_absent=child_absent,
    )


class _ParentDeadline:
    """A real-monotonic deadline whose expiry does not depend on asyncio dispatch."""

    def __init__(self, deadline: float) -> None:
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._expired = False
        self._claimed = False
        self.deadline = deadline
        self._thread = threading.Thread(target=self._watch, args=(self._stop,), daemon=True)
        self._thread.start()

    def _watch(self, stop: threading.Event) -> None:
        if not stop.wait(max(0.0, self.deadline - time.monotonic())):
            with self._lock:
                if self._stop is stop and not self._claimed:
                    self._expired = True

    def reset(self, deadline: float) -> None:
        """Move the default deadline after worker setup has signalled readiness."""

        with self._lock:
            if self._claimed:
                return
            self._stop.set()
            self.deadline = deadline
            self._expired = False
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._watch, args=(self._stop,), daemon=True)
            self._thread.start()

    def expired(self) -> bool:
        with self._lock:
            if not self._claimed and time.monotonic() >= self.deadline:
                self._expired = True
            return self._expired

    def claim_receipt(self) -> bool:
        """Atomically permit one receipt only while the parent deadline is still live."""

        with self._lock:
            if self._expired or time.monotonic() >= self.deadline:
                self._expired = True
                return False
            self._claimed = True
            self._stop.set()
            return True

    def close(self) -> None:
        self._stop.set()


async def run_completion_driven(
    contract: RunnerContract,
    factory: RegisteredFlowFactory,
    *,
    outer_deadline_seconds: float | None = None,
) -> dict[str, object]:
    """Run the whole capability lifecycle inside one disposable, exactly reaped process.

    The default parent-owned deadline is the frozen scoring cap plus the 190-second outer cleanup
    grace.  An explicit shorter deadline is an operator cancellation seam: it never changes the
    child contract or produces a scored receipt.
    """

    if not isinstance(contract, RunnerContract) or not isinstance(factory, RegisteredFlowFactory):
        raise CapabilityRunnerError("public runner requires a registered flow factory")
    supervisor_start = time.monotonic()
    maximum = float(contract.scoring_seconds + contract.cleanup_grace_seconds)
    timeout = maximum if outer_deadline_seconds is None else outer_deadline_seconds
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(float(timeout))
        or not 0 < float(timeout) <= maximum
    ):
        raise CapabilityRunnerError("outer supervisor deadline is invalid")
    if "CODEX_HOME" in factory.provider_auth_environment and not sys.platform.startswith("linux"):
        raise CapabilitySupervisorError(
            "containment_unavailable",
            terminated=False,
            killed=False,
            child_reaped=True,
            child_absent=True,
        )
    request = {
        "schema": "rapido-offline-capability-supervisor-request-v1",
        "contract": _contract_public(contract),
        "factory": _factory_public(factory),
    }
    _public_scan(request, "supervisor_request")
    request_bytes = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(request_bytes) > _MAX_SUPERVISOR_REQUEST_BYTES:
        raise CapabilityRunnerError("supervisor request exceeds its bound")

    read_descriptor = -1
    write_descriptor = -1
    linux_containment = sys.platform.startswith("linux")
    linux_parent_boundary = False
    linux_parent_previous = False
    linux_parent_configured = False
    proof_read_descriptor = -1
    proof_write_descriptor = -1
    process: subprocess.Popen[bytes] | None = None
    parent_deadline = _ParentDeadline(supervisor_start + min(float(timeout), _WORKER_READY_SECONDS))
    try:
        read_descriptor, write_descriptor = os.pipe()
        os.set_blocking(read_descriptor, False)
        if linux_containment:
            if not _LINUX_SUPERVISOR_LOCK.acquire(blocking=False):
                raise CapabilitySupervisorError(
                    "containment_unavailable",
                    terminated=False,
                    killed=False,
                    child_reaped=True,
                    child_absent=True,
                )
            linux_parent_boundary = True
            if _linux_owned_descendants():
                raise CapabilityRunnerError("Linux supervisor child set is not dedicated")
            linux_parent_previous = _enable_linux_child_adoption()
            linux_parent_configured = True
            if _linux_owned_descendants():
                raise CapabilityRunnerError("Linux supervisor child set changed")
            proof_read_descriptor, proof_write_descriptor = os.pipe()
            os.set_blocking(proof_read_descriptor, False)
        command = (
            sys.executable,
            "-c",
            (
                "from rapido.offline_capability_runner import "
                + (
                    "_linux_containment_main as entrypoint"
                    if linux_containment
                    else "_subprocess_worker_main as entrypoint"
                )
                + (
                    "; import sys; entrypoint(int(sys.argv[1]), int(sys.argv[2]))"
                    if linux_containment
                    else "; import sys; entrypoint(int(sys.argv[1]))"
                )
            ),
            str(write_descriptor),
            *((str(proof_write_descriptor),) if linux_containment else ()),
        )
    except BaseException:
        parent_deadline.close()
        for descriptor in (
            write_descriptor,
            read_descriptor,
            proof_write_descriptor,
            proof_read_descriptor,
        ):
            if descriptor >= 0:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
        if linux_parent_boundary:
            try:
                if linux_parent_configured:
                    _restore_linux_child_adoption(linux_parent_previous)
            finally:
                _LINUX_SUPERVISOR_LOCK.release()
        raise
    try:
        try:
            process = subprocess.Popen(  # noqa: ASYNC220 - cancellation needs synchronous exact reap
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                pass_fds=(
                    (write_descriptor, proof_write_descriptor)
                    if linux_containment
                    else (write_descriptor,)
                ),
                start_new_session=True,
                env=_worker_environment(factory),
            )
        except OSError:
            raise CapabilitySupervisorError(
                "worker_launch_failure",
                terminated=False,
                killed=False,
                child_reaped=True,
                child_absent=True,
            ) from None
        os.close(write_descriptor)
        write_descriptor = -1
        if proof_write_descriptor >= 0:
            os.close(proof_write_descriptor)
            proof_write_descriptor = -1
        if process.stdin is None:  # pragma: no cover - Popen contract
            raise CapabilityRunnerError("capability worker input pipe is unavailable")
        try:
            process.stdin.write(request_bytes)
            process.stdin.close()
        except BrokenPipeError:
            process.stdin.close()

        buffer = bytearray()
        expected: int | None = None
        failure_label: str | None = None
        ready_received = False
        message_row: Mapping[str, object] | None = None
        while message_row is None:
            if parent_deadline.expired():
                failure_label = "outer_deadline"
                break
            try:
                chunk = os.read(read_descriptor, 65_536)
            except BlockingIOError:
                chunk = None
            if chunk:
                buffer.extend(chunk)
                if len(buffer) > (_MAX_SUPERVISOR_RESPONSE_BYTES * 2) + 8:
                    failure_label = "worker_response_oversize"
                    break
                while message_row is None:
                    if expected is None:
                        if len(buffer) < 4:
                            break
                        expected = int.from_bytes(buffer[:4], "big")
                        if expected > _MAX_SUPERVISOR_RESPONSE_BYTES:
                            failure_label = "worker_response_oversize"
                            break
                    if len(buffer) < expected + 4:
                        break
                    frame = bytes(buffer[4 : expected + 4])
                    del buffer[: expected + 4]
                    expected = None
                    try:
                        parsed = _mapping(json.loads(frame), "worker response")
                        if parsed.get("schema") != SUPERVISOR_MESSAGE_SCHEMA:
                            raise CapabilityRunnerError("worker response envelope is invalid")
                        _public_scan(parsed, "worker_response")
                    except (CapabilityRunnerError, json.JSONDecodeError, UnicodeError):
                        failure_label = "worker_protocol"
                        break
                    kind = parsed.get("kind")
                    if not ready_received:
                        if set(parsed) != {"schema", "kind"} or kind != "ready":
                            message_row = parsed
                            break
                        if parent_deadline.expired():
                            failure_label = "outer_deadline"
                            break
                        ready_received = True
                        if outer_deadline_seconds is None:
                            parent_deadline.reset(time.monotonic() + maximum)
                        continue
                    if kind == "ready":
                        failure_label = "worker_protocol"
                        break
                    message_row = parsed
                if failure_label is not None:
                    break
            if process.poll() is not None and chunk == b"":
                failure_label = "worker_no_response"
                break
            await asyncio.sleep(_SUPERVISOR_POLL_SECONDS)

        process_evidence = _terminate_and_reap(
            process,
            linux_containment=linux_containment,
            linux_parent_boundary=linux_parent_boundary,
            proof_descriptor=proof_read_descriptor,
        )
        process = None
        if parent_deadline.expired():
            failure_label = "outer_deadline"
        if failure_label is not None:
            raise _closed_supervisor_error(failure_label, process_evidence)
        if message_row is None or expected is not None or buffer:
            raise _closed_supervisor_error("worker_protocol", process_evidence)
        try:
            if message_row.get("schema") != SUPERVISOR_MESSAGE_SCHEMA or message_row.get(
                "kind"
            ) not in {"receipt", "error"}:
                raise CapabilityRunnerError("worker response envelope is invalid")
        except CapabilityRunnerError:
            raise _closed_supervisor_error("worker_protocol", process_evidence) from None
        if message_row["kind"] == "error":
            if parent_deadline.expired():
                raise _closed_supervisor_error("outer_deadline", process_evidence)
            if set(message_row) != {"schema", "kind", "failure_label"}:
                raise _closed_supervisor_error("worker_protocol", process_evidence)
            label = message_row["failure_label"]
            if label not in {
                "worker_failure",
                "worker_nonquiescent",
                "worker_response_oversize",
            }:
                raise _closed_supervisor_error("worker_protocol", process_evidence)
            raise _closed_supervisor_error(label, process_evidence)  # type: ignore[arg-type]
        if set(message_row) != {"schema", "kind", "receipt"}:
            raise _closed_supervisor_error("worker_protocol", process_evidence)
        try:
            receipt = _mapping(message_row["receipt"], "worker receipt")
            validate_runner_receipt(receipt)
            if not _receipt_matches_contract(receipt, contract):
                raise CapabilityRunnerError("worker receipt changed the contract")
        except CapabilityRunnerError:
            raise _closed_supervisor_error("worker_receipt_invalid", process_evidence) from None
        if not parent_deadline.claim_receipt():
            raise _closed_supervisor_error("outer_deadline", process_evidence)
        return dict(receipt)
    except asyncio.CancelledError:
        if process is not None:
            _terminate_and_reap(
                process,
                linux_containment=linux_containment,
                linux_parent_boundary=linux_parent_boundary,
                proof_descriptor=proof_read_descriptor,
            )
            process = None
        raise
    finally:
        parent_deadline.close()
        if write_descriptor >= 0:
            os.close(write_descriptor)
        if proof_write_descriptor >= 0:
            os.close(proof_write_descriptor)
        os.close(read_descriptor)
        if process is not None:
            if process.stdin is not None:
                try:
                    process.stdin.close()
                except OSError:
                    pass
            _terminate_and_reap(
                process,
                linux_containment=linux_containment,
                linux_parent_boundary=linux_parent_boundary,
                proof_descriptor=proof_read_descriptor,
            )
        if proof_read_descriptor >= 0:
            os.close(proof_read_descriptor)
        if linux_parent_boundary:
            try:
                _restore_linux_child_adoption(linux_parent_previous)
            finally:
                _LINUX_SUPERVISOR_LOCK.release()
