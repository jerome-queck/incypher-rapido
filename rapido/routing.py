"""Closed, deterministic failure routing for the durable control path."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Literal

FailureKind = Literal[
    "board",
    "container",
    "disagreement",
    "policy",
    "provenance",
    "quota",
    "timeout",
    "tool",
]
FailureOrigin = Literal["board", "container"]
Disposition = Literal["contain", "dispatch"]

FAILURE_KINDS = frozenset(
    {"board", "container", "disagreement", "policy", "provenance", "quota", "timeout", "tool"}
)
FAILURE_ORIGINS = frozenset({"board", "container"})
DISPOSITIONS = frozenset({"contain", "dispatch"})
ROLES = frozenset({"recovery", "specialist", "verifier"})
_POLICY_FAILURES = frozenset({"cyber_policy", "misalignment_policy_violation"})
_PROVENANCE_FAILURES = frozenset({"candidate_provenance"})
_TIMEOUT_FAILURES = frozenset({"timeout"})
_QUOTA_FAILURES = frozenset(
    {
        "rate_limit_exceeded",
        "response_too_many_failed_attempts",
        "server_overloaded",
        "session_budget_exceeded",
        "usage_limit_exceeded",
    }
)
_CONTAINER_FAILURES = frozenset({"native_runtime", "operating_system", "process_restart"})
_ROUTABLE_TOOL_FAILURES = frozenset(
    {
        "active_turn_not_steerable",
        "bad_request",
        "context_window_exceeded",
        "invalid_value",
        "no_progress",
        "response_stream_connection_failed",
        "response_stream_disconnected",
        "sandbox_error",
        "solver_output",
        "thread_rollback_failed",
    }
)
_UNSAFE_NATIVE_FAILURES = frozenset(
    {
        "cancelled",
        "http_connection_failed",
        "internal_server_error",
        "interrupted",
        "other",
        "unauthorized",
        "unknown",
    }
)
KNOWN_FAILURE_CLASSES = (
    _POLICY_FAILURES
    | _PROVENANCE_FAILURES
    | _TIMEOUT_FAILURES
    | _QUOTA_FAILURES
    | _CONTAINER_FAILURES
    | _ROUTABLE_TOOL_FAILURES
    | _UNSAFE_NATIVE_FAILURES
)
_ROUTE_FIELDS = (
    "role",
    "tactic",
    "context_profile",
    "tool_policy",
    "verification_recipe",
    "backoff_policy",
    "attempt_seconds",
    "deadline_policy",
    "effect_policy",
    "model",
    "effort",
    "workspace_generation",
)
ROUTE_AXES = frozenset(_ROUTE_FIELDS)


def _bounded(value: object, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 100
        or any(ord(char) < 32 for char in value)
        or "{" in value
        or "}" in value
    ):
        raise ValueError(f"route {field} is invalid")
    return value


@dataclass(frozen=True)
class RouteSpec:
    role: str
    tactic: str
    context_profile: str
    tool_policy: str
    verification_recipe: str
    backoff_policy: str
    attempt_seconds: int
    deadline_policy: str
    effect_policy: str
    model: str
    effort: str
    workspace_generation: int

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ValueError("route role is invalid")
        for field in _ROUTE_FIELDS:
            if field in {"attempt_seconds", "workspace_generation"}:
                continue
            _bounded(getattr(self, field), field)
        if type(self.attempt_seconds) is not int or not 1 <= self.attempt_seconds <= 19_800:
            raise ValueError("route attempt_seconds is invalid")
        if (
            type(self.workspace_generation) is not int
            or not 0 <= self.workspace_generation <= 10_000
        ):
            raise ValueError("route workspace_generation is invalid")

    def as_dict(self) -> dict[str, object]:
        return {field: getattr(self, field) for field in _ROUTE_FIELDS}

    @classmethod
    def from_dict(cls, value: object) -> RouteSpec:
        if not isinstance(value, dict) or set(value) != set(_ROUTE_FIELDS):
            raise ValueError("durable route has an invalid shape")
        return cls(**value)

    @property
    def fingerprint(self) -> str:
        encoded = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()

    def changed_axes(self, successor: RouteSpec) -> tuple[str, ...]:
        return tuple(
            field for field in _ROUTE_FIELDS if getattr(self, field) != getattr(successor, field)
        )


@dataclass(frozen=True)
class FailureSignal:
    kind: FailureKind
    subreason: str

    def __post_init__(self) -> None:
        if self.kind not in FAILURE_KINDS:
            raise ValueError("failure kind is invalid")
        _bounded(self.subreason, "failure subreason")


@dataclass(frozen=True)
class RouteRequest:
    failure: FailureSignal
    current: RouteSpec
    used_fingerprints: frozenset[str]
    attempts_remaining: bool
    remaining_milliseconds: int
    effects_safe: bool = True
    instances_safe: bool = True


@dataclass(frozen=True)
class RouteDecision:
    disposition: Disposition
    rule_id: str
    failure: FailureSignal
    source_fingerprint: str
    successor: RouteSpec | None
    changed_axes: tuple[str, ...]
    reason: str


def baseline_route(
    *, model: str, effort: str, attempt_seconds: int, workspace_generation: int = 0
) -> RouteSpec:
    return RouteSpec(
        role="specialist",
        tactic="baseline",
        context_profile="fresh_lane_with_typed_same_run_history",
        tool_policy="bounded_registry",
        verification_recipe="none",
        backoff_policy="none",
        attempt_seconds=attempt_seconds,
        deadline_policy="minimum_of_attempt_and_run_deadline",
        effect_policy="controller_only",
        model=model,
        effort=effort,
        workspace_generation=workspace_generation,
    )


def instance_follow_on_route(current: RouteSpec) -> RouteSpec:
    """Move a dynamic challenge from local analysis to one shared live instance."""
    return replace(
        current,
        role="recovery",
        tactic="instance_enabled_follow_on",
        context_profile="typed_local_history_with_fresh_target",
        tool_policy="bounded_registry_with_assigned_target",
        verification_recipe="source_reobservation_after_local_analysis",
        workspace_generation=current.workspace_generation + 1,
    )


def classify_failure(
    *,
    terminal: str,
    failure_origin: FailureOrigin | None,
    failure_classes: frozenset[str],
    candidate_identity_count: int,
    attempt_count: int,
) -> FailureSignal | None:
    """Project private outcomes and a typed catch-boundary origin into eight classes."""
    unknown = failure_classes - KNOWN_FAILURE_CLASSES
    if unknown:
        raise ValueError("unrecognized durable failure class")
    if failure_origin is not None and failure_origin not in FAILURE_ORIGINS:
        raise ValueError("failure origin is invalid")
    if terminal == "error" and failure_origin is not None:
        return FailureSignal(failure_origin, f"{failure_origin}_catch_boundary_failure")
    if terminal == "solved" or terminal == "candidate" and candidate_identity_count == 0:
        return None
    if candidate_identity_count > 0:
        return FailureSignal(
            "disagreement",
            (
                "distinct_source_candidates"
                if candidate_identity_count > 1
                else "retained_candidate_requires_verification"
            ),
        )
    groups: tuple[tuple[FailureKind, frozenset[str]], ...] = (
        ("policy", _POLICY_FAILURES),
        ("provenance", _PROVENANCE_FAILURES),
        ("timeout", _TIMEOUT_FAILURES),
        ("quota", _QUOTA_FAILURES),
        ("tool", _UNSAFE_NATIVE_FAILURES),
        ("tool", _ROUTABLE_TOOL_FAILURES),
        ("container", _CONTAINER_FAILURES),
    )
    for kind, classes in groups:
        matched = sorted(failure_classes & classes)
        if matched:
            return FailureSignal(kind, matched[0])
    if terminal == "error" and attempt_count == 0:
        return FailureSignal("container", "unclassified_pre_lane_failure")
    if terminal == "unsolved" and attempt_count > 0:
        return FailureSignal("tool", "stalled_without_candidate")
    return None


def _terminal(request: RouteRequest, rule_id: str, reason: str) -> RouteDecision:
    return RouteDecision(
        disposition="contain",
        rule_id=rule_id,
        failure=request.failure,
        source_fingerprint=request.current.fingerprint,
        successor=None,
        changed_axes=(),
        reason=reason,
    )


def route_failure(request: RouteRequest) -> RouteDecision:
    """Map one typed failure to a sanctioned changed route or containment."""
    if type(request.attempts_remaining) is not bool:
        raise TypeError("attempts_remaining must be boolean")
    if type(request.remaining_milliseconds) is not int or request.remaining_milliseconds < 0:
        raise ValueError("remaining_milliseconds is invalid")
    if type(request.effects_safe) is not bool or type(request.instances_safe) is not bool:
        raise TypeError("safety gates must be boolean")
    if not request.attempts_remaining:
        return _terminal(request, "route_budget_exhausted", "no successor episode remains")

    failure = request.failure
    successor: RouteSpec | None = None
    rule_id = ""
    if failure.kind == "policy":
        return _terminal(request, "policy_unapproved", "no validated authorized route fact exists")
    if failure.kind == "provenance":
        return _terminal(
            request,
            "provenance_rejected",
            "unproven candidate material cannot enter the private verifier path",
        )
    if failure.kind == "disagreement":
        if failure.subreason not in {
            "board_rejected_candidate",
            "distinct_source_candidates",
            "retained_candidate_requires_verification",
        }:
            return _terminal(
                request,
                "disagreement_verifier_unavailable",
                "no durable private candidate fact authorizes verifier dispatch",
            )
        if failure.subreason == "board_rejected_candidate":
            rule_id = "board_rejection_recovery_v1"
            successor = replace(
                request.current,
                role="recovery",
                tactic="alternate_candidate_after_board_rejection",
                context_profile="typed_facts_without_rejected_candidate",
                workspace_generation=request.current.workspace_generation + 1,
            )
        else:
            rule_id = "private_source_reobservation_v1"
            successor = replace(
                request.current,
                role="verifier",
                tactic="independent_source_reobservation",
                context_profile="fresh_source_only_no_candidate_carry",
                verification_recipe="fresh_source_reobservation_v1",
            )
    if failure.kind == "timeout":
        return _terminal(
            request,
            "timeout_without_checkpoint",
            "no committed and restorable checkpoint fact exists",
        )
    if failure.kind == "quota":
        if request.remaining_milliseconds < 61_000:
            return _terminal(
                request,
                "quota_wait_exceeds_run_deadline",
                "the bounded quota wait cannot fit inside the original run deadline",
            )
        rule_id = "quota_bounded_wait_v1"
        successor = replace(
            request.current,
            tactic="resume_after_quota_backoff",
            backoff_policy="bounded_60_seconds",
        )
    if failure.kind == "board":
        return _terminal(
            request,
            "board_contract_unapproved",
            "no validated mutation-safe Board route fact exists",
        )
    if failure.kind == "tool":
        if failure.subreason in _UNSAFE_NATIVE_FAILURES:
            return _terminal(
                request,
                "tool_unsafe_native_failure",
                "authorization or unclassified provider failure is not retryable",
            )
        if failure.subreason == "stalled_without_candidate":
            rule_id = "typed_peer_recovery_v1"
            successor = replace(
                request.current,
                role="recovery",
                tactic="typed_peer_recovery",
                context_profile="durable_facts_only",
                workspace_generation=request.current.workspace_generation + 1,
            )
        else:
            rule_id = "tool_alternate_representation_v1"
            successor = replace(
                request.current,
                tactic="alternate_representation",
                context_profile="fresh_without_failed_tool_assumption",
            )
    elif failure.kind == "container":
        if failure.subreason == "unclassified_pre_lane_failure":
            return _terminal(
                request,
                "container_origin_unknown",
                "no typed catch-boundary origin proves a local recovery route",
            )
        if not request.effects_safe or not request.instances_safe:
            return _terminal(
                request,
                "container_effect_fenced",
                "pending effects or instances prevent recovery dispatch",
            )
        rule_id = "container_fresh_workspace_v1"
        successor = replace(
            request.current,
            role="recovery",
            tactic="fresh_workspace_recovery",
            context_profile="durable_facts_only",
            workspace_generation=(
                request.current.workspace_generation + 1
                if failure.subreason == "process_restart"
                else 1
            ),
        )
    elif failure.kind not in {"disagreement", "quota"}:  # pragma: no cover - closed above
        raise AssertionError("unreachable failure kind")

    assert successor is not None
    if successor.model != request.current.model or successor.effort != request.current.effort:
        raise ValueError("routing cannot change exact model or effort")
    if successor.effect_policy != request.current.effect_policy:
        raise ValueError("routing cannot change effect authority")
    changed_axes = request.current.changed_axes(successor)
    if not changed_axes or successor.fingerprint == request.current.fingerprint:
        return _terminal(request, "no_changed_route", "proposed route changed no material axis")
    if successor.fingerprint in request.used_fingerprints:
        return _terminal(request, "duplicate_route", "proposed route was already admitted")
    if request.remaining_milliseconds < 1_000:
        return _terminal(request, "run_deadline", "insufficient run time remains")
    return RouteDecision(
        disposition="dispatch",
        rule_id=rule_id,
        failure=failure,
        source_fingerprint=request.current.fingerprint,
        successor=successor,
        changed_axes=changed_axes,
        reason="sanctioned material route change",
    )


__all__ = [
    "DISPOSITIONS",
    "FAILURE_KINDS",
    "FAILURE_ORIGINS",
    "KNOWN_FAILURE_CLASSES",
    "ROUTE_AXES",
    "Disposition",
    "FailureKind",
    "FailureOrigin",
    "FailureSignal",
    "RouteDecision",
    "RouteRequest",
    "RouteSpec",
    "baseline_route",
    "classify_failure",
    "instance_follow_on_route",
    "route_failure",
]
