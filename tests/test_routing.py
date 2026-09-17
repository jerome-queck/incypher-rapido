from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

import pytest

from rapido.routing import (
    FAILURE_KINDS,
    FailureSignal,
    RouteRequest,
    baseline_route,
    classify_failure,
    route_failure,
)


def _request(kind: str, *, subreason: str | None = None, **changes: object) -> RouteRequest:
    current = baseline_route(
        model="gpt-daybreak-blue-latest",
        effort="xhigh",
        attempt_seconds=900,
    )
    values: dict[str, object] = {
        "failure": FailureSignal(kind, subreason or f"fixture_{kind}"),
        "current": current,
        "used_fingerprints": frozenset({current.fingerprint}),
        "attempts_remaining": True,
        "remaining_milliseconds": 10_000,
    }
    values.update(changes)
    return RouteRequest(**values)


@pytest.mark.parametrize(
    ("kind", "disposition"),
    [
        ("board", "contain"),
        ("container", "dispatch"),
        ("disagreement", "contain"),
        ("policy", "contain"),
        ("provenance", "contain"),
        ("quota", "contain"),
        ("timeout", "contain"),
        ("tool", "dispatch"),
    ],
)
def test_exact_eight_default_routes_are_fail_safe(kind: str, disposition: str) -> None:
    assert len(FAILURE_KINDS) == 8
    decision = route_failure(_request(kind))
    assert decision.disposition == disposition
    if disposition == "dispatch":
        assert decision.successor is not None
        assert decision.changed_axes
        assert decision.successor.fingerprint != decision.source_fingerprint
        assert decision.successor.model == "gpt-daybreak-blue-latest"
        assert decision.successor.effort == "xhigh"
        assert decision.successor.effect_policy == "controller_only"
    else:
        assert decision.successor is None
        assert decision.changed_axes == ()


@pytest.mark.parametrize(
    "subreason",
    [
        "unauthorized",
        "http_connection_failed",
        "internal_server_error",
        "other",
        "unknown",
    ],
)
def test_authorization_and_unknown_native_failures_are_contained(subreason: str) -> None:
    decision = route_failure(_request("tool", subreason=subreason))
    assert decision.disposition == "contain"
    assert decision.rule_id == "tool_unsafe_native_failure"


def test_quota_failure_earns_one_bounded_wait_without_model_fallback() -> None:
    decision = route_failure(
        _request(
            "quota",
            subreason="rate_limit_exceeded",
            remaining_milliseconds=120_000,
        )
    )
    assert decision.disposition == "dispatch"
    assert decision.rule_id == "quota_bounded_wait_v1"
    assert decision.successor is not None
    assert decision.changed_axes == ("tactic", "backoff_policy")
    assert decision.successor.backoff_policy == "bounded_60_seconds"
    assert decision.successor.model == "gpt-daybreak-blue-latest"
    assert decision.successor.effort == "xhigh"


def test_productive_timeout_earns_exactly_one_changed_recovery() -> None:
    first = route_failure(_request("timeout", subreason="timeout", durable_observation_count=12))
    assert first.disposition == "dispatch"
    assert first.rule_id == "typed_timeout_recovery_v1"
    assert first.successor is not None
    assert first.successor.role == "recovery"
    assert set(first.changed_axes) == {
        "role",
        "tactic",
        "context_profile",
        "workspace_generation",
    }

    interleaved = route_failure(
        RouteRequest(
            failure=FailureSignal("tool", "solver_output"),
            current=first.successor,
            used_fingerprints=frozenset({first.source_fingerprint, first.successor.fingerprint}),
            attempts_remaining=True,
            remaining_milliseconds=10_000,
        )
    )
    assert interleaved.disposition == "dispatch"
    assert interleaved.successor is not None

    second = route_failure(
        RouteRequest(
            failure=FailureSignal("timeout", "timeout"),
            current=interleaved.successor,
            used_fingerprints=frozenset(
                {
                    first.source_fingerprint,
                    first.successor.fingerprint,
                    interleaved.successor.fingerprint,
                }
            ),
            attempts_remaining=True,
            remaining_milliseconds=10_000,
            durable_observation_count=1,
            timeout_recovery_used=True,
        )
    )
    assert second.disposition == "contain"
    assert second.rule_id == "timeout_recovery_exhausted"


@pytest.mark.parametrize(
    "changes",
    (
        {"durable_observation_count": 0},
        {"durable_observation_count": 1, "effects_safe": False},
        {"durable_observation_count": 1, "instances_safe": False},
        {"durable_observation_count": 1, "attempts_remaining": False},
    ),
)
def test_timeout_without_safe_evidence_or_budget_is_contained(
    changes: dict[str, object],
) -> None:
    assert route_failure(_request("timeout", subreason="timeout", **changes)).disposition == (
        "contain"
    )


@pytest.mark.parametrize(
    "subreason", ("distinct_source_candidates", "retained_candidate_requires_verification")
)
def test_durable_private_candidate_facts_dispatch_verifier(subreason: str) -> None:
    decision = route_failure(_request("disagreement", subreason=subreason))
    assert decision.disposition == "dispatch"
    assert decision.successor is not None
    assert decision.successor.role == "verifier"
    assert decision.successor.verification_recipe == "fresh_source_reobservation_v1"
    assert set(decision.changed_axes) == {
        "role",
        "tactic",
        "context_profile",
        "verification_recipe",
    }
    assert decision.successor.attempt_seconds == 900
    assert decision.successor.deadline_policy == "minimum_of_attempt_and_run_deadline"


def test_board_rejected_candidate_dispatches_changed_recovery_route() -> None:
    decision = route_failure(_request("disagreement", subreason="board_rejected_candidate"))
    assert decision.disposition == "dispatch"
    assert decision.rule_id == "board_rejection_recovery_v1"
    assert decision.successor is not None
    assert decision.successor.role == "recovery"
    assert decision.successor.tactic == "alternate_candidate_after_board_rejection"
    assert decision.changed_axes


def test_classifier_uses_typed_pre_lane_origin() -> None:
    board = classify_failure(
        terminal="error",
        failure_origin="board",
        failure_classes=frozenset(),
        candidate_identity_count=0,
        attempt_count=0,
    )
    container = classify_failure(
        terminal="error",
        failure_origin="container",
        failure_classes=frozenset(),
        candidate_identity_count=0,
        attempt_count=0,
    )
    assert board == FailureSignal("board", "board_catch_boundary_failure")
    assert container == FailureSignal("container", "container_catch_boundary_failure")


@pytest.mark.parametrize(
    "failure_class",
    [
        "unauthorized",
        "http_connection_failed",
        "internal_server_error",
        "unknown",
    ],
)
def test_every_unsafe_native_class_maps_to_containment(failure_class: str) -> None:
    signal = classify_failure(
        terminal="error",
        failure_origin=None,
        failure_classes=frozenset({failure_class}),
        candidate_identity_count=0,
        attempt_count=2,
    )
    assert signal is not None
    assert route_failure(_request(signal.kind, subreason=signal.subreason)).disposition == "contain"


def test_persistent_failures_cannot_repeat_changed_routes() -> None:
    for kind, subreason in (("tool", "solver_output"), ("container", "native_runtime")):
        first = route_failure(_request(kind, subreason=subreason))
        assert first.successor is not None
        second = route_failure(
            RouteRequest(
                failure=FailureSignal(kind, subreason),
                current=first.successor,
                used_fingerprints=frozenset(
                    {first.source_fingerprint, first.successor.fingerprint}
                ),
                attempts_remaining=True,
                remaining_milliseconds=10_000,
            )
        )
        assert second.disposition == "contain"
        assert second.rule_id == "no_changed_route"
        assert second.successor is None


def test_two_hundred_replays_have_one_canonical_decision_digest() -> None:
    requests = tuple(_request(kind) for kind in sorted(FAILURE_KINDS))

    def digest() -> str:
        encoded = json.dumps(
            [asdict(route_failure(request)) for request in requests],
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(encoded.encode()).hexdigest()

    assert len({digest() for _ in range(200)}) == 1


def test_unknown_failure_kind_and_nested_route_values_are_rejected() -> None:
    with pytest.raises(ValueError, match="failure kind"):
        FailureSignal("unknown", "fixture")
    route = baseline_route(model="m", effort="xhigh", attempt_seconds=10).as_dict()
    route["tactic"] = ["safe", "FLAG{nested-secret}"]
    with pytest.raises((TypeError, ValueError)):
        from rapido.routing import RouteSpec

        RouteSpec.from_dict(route)
