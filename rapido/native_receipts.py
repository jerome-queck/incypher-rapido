"""Versioned, privacy-closed native usage and span receipts.

The caller supplies controller-observed intervals, budgets, native completion events, and
sanitized tool-call records.  This module emits only fixed identities, enums, counts, and
durations.  Raw arguments, prose, paths, authorities, candidates, and digests are never copied.
"""

from __future__ import annotations

import re
from collections import Counter, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Literal

from .reporting import USAGE_FIELDS, USAGE_POLICY

ATTEMPT_RECEIPT_SCHEMA: Final = "rapido-native-attempt-receipt-v1"
SUMMARY_RECEIPT_SCHEMA: Final = "rapido-native-receipt-summary-v1"

NativeOutcome = Literal[
    "completed",
    "timeout",
    "provider_failure",
    "cancelled",
    "inconclusive",
]
SpanStatus = Literal["completed", "failed", "cancelled", "not_run"]

_OUTCOMES = frozenset(NativeOutcome.__args__)
_SPAN_STATUSES = frozenset(SpanStatus.__args__)
_SPAN_STAGES = frozenset(
    {
        "cleanup",
        "evidence",
        "first_turn",
        "fixture_setup",
        "model_validation",
        "queue",
        "repair_turn",
        "startup",
    }
)
_FAILURE_STAGES = frozenset({"arguments", "execution", "result"})
_PUBLIC_ID = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,95}\Z")
_TOOL_ID = re.compile(r"[a-z0-9_]{1,96}\Z")
_USAGE_ALIASES: Final = {
    "input_tokens": ("input_tokens", "inputTokens"),
    "output_tokens": ("output_tokens", "outputTokens"),
    "cached_input_tokens": ("cached_input_tokens", "cachedInputTokens"),
    "reasoning_tokens": (
        "reasoning_tokens",
        "reasoningTokens",
        "reasoning_output_tokens",
        "reasoningOutputTokens",
    ),
}


@dataclass(frozen=True, order=True)
class AttemptKey:
    task_id: str
    arm_id: str

    def validated(self) -> AttemptKey:
        for name, value in (("task_id", self.task_id), ("arm_id", self.arm_id)):
            if not isinstance(value, str) or _PUBLIC_ID.fullmatch(value) is None:
                raise ValueError(f"{name} is not a public receipt identity")
        return self


@dataclass(frozen=True)
class Span:
    stage: str
    status: SpanStatus
    start_offset_milliseconds: int | None
    end_offset_milliseconds: int | None

    def public(self) -> dict[str, object]:
        if self.stage not in _SPAN_STAGES:
            raise ValueError("span stage is not registered")
        if self.status not in _SPAN_STATUSES:
            raise ValueError("span status is not registered")
        start = _optional_nonnegative(self.start_offset_milliseconds, "span start")
        end = _optional_nonnegative(self.end_offset_milliseconds, "span end")
        if self.status == "not_run":
            if start is not None or end is not None:
                raise ValueError("not-run spans cannot contain an interval")
            duration = None
        else:
            if start is None or end is None or end < start:
                raise ValueError("observed span requires one monotonic interval")
            duration = end - start
        return {
            "stage": self.stage,
            "status": self.status,
            "start_offset_milliseconds": start,
            "end_offset_milliseconds": end,
            "duration_milliseconds": duration,
        }


@dataclass(frozen=True)
class Budget:
    configured_milliseconds: int
    granted_milliseconds: int
    remaining_after_first_milliseconds: int | None
    remaining_terminal_milliseconds: int | None

    def public(self) -> dict[str, int | None]:
        configured = _nonnegative(self.configured_milliseconds, "configured budget")
        granted = _nonnegative(self.granted_milliseconds, "granted budget")
        after_first = _optional_nonnegative(
            self.remaining_after_first_milliseconds, "remaining first-turn budget"
        )
        terminal = _optional_nonnegative(
            self.remaining_terminal_milliseconds, "remaining terminal budget"
        )
        if granted > configured:
            raise ValueError("granted budget exceeds configured budget")
        if after_first is not None and after_first > granted:
            raise ValueError("remaining first-turn budget exceeds grant")
        if terminal is not None and terminal > granted:
            raise ValueError("remaining terminal budget exceeds grant")
        if after_first is not None and terminal is not None and terminal > after_first:
            raise ValueError("terminal budget increased after the first turn")
        return {
            "configured_milliseconds": configured,
            "granted_milliseconds": granted,
            "remaining_after_first_milliseconds": after_first,
            "remaining_terminal_milliseconds": terminal,
        }


def build_native_attempt_receipt(
    *,
    key: AttemptKey,
    outcome: NativeOutcome,
    spans: Sequence[Span],
    budget: Budget,
    first_event: Mapping[str, object] | None,
    final_event: Mapping[str, object] | None,
    first_turn_calls: Sequence[Mapping[str, object]],
    repair_turn_calls: Sequence[Mapping[str, object]],
    cumulative_calls: Sequence[Mapping[str, object]],
    repair_attempted: bool,
) -> dict[str, object]:
    """Build one exact, secret-free attempt receipt.

    Native usage snapshots are cumulative.  A repair therefore counts the final snapshot once;
    its delta is emitted only for fields with monotonic first/final observations.
    """
    key.validated()
    if outcome not in _OUTCOMES:
        raise ValueError("native outcome is not registered")
    if type(repair_attempted) is not bool:
        raise TypeError("repair_attempted must be boolean")
    public_spans = [span.public() for span in spans]
    stages = [str(span["stage"]) for span in public_spans]
    if len(stages) != len(set(stages)):
        raise ValueError("attempt contains duplicate span stages")
    if not repair_attempted and repair_turn_calls:
        raise ValueError("non-repair attempt contains repair calls")
    if len(cumulative_calls) != len(first_turn_calls) + len(repair_turn_calls):
        raise ValueError("cumulative call count does not reconcile to turn calls")

    first_usage = _usage_snapshot(first_event)
    final_usage = _usage_snapshot(final_event)
    accounted: dict[str, int | None] = {}
    repair_delta: dict[str, int | None] = {}
    repair_delta_status: dict[str, str] = {}
    for field in USAGE_FIELDS:
        first_value = first_usage[field]
        final_value = final_usage[field]
        field_monotonic = first_value is None or final_value is None or final_value >= first_value
        accounted[field] = final_value if field_monotonic else None
        if not repair_attempted or first_value is None or final_value is None:
            repair_delta[field] = None
            repair_delta_status[field] = "not_applicable" if not repair_attempted else "incomplete"
        elif field_monotonic:
            repair_delta[field] = final_value - first_value
            repair_delta_status[field] = "monotone"
        else:
            repair_delta[field] = None
            repair_delta_status[field] = "nonmonotone"

    tool_accounting = _tool_accounting(first_turn_calls, repair_turn_calls, cumulative_calls)
    return {
        "schema": ATTEMPT_RECEIPT_SCHEMA,
        "attempt": {"task_id": key.task_id, "arm_id": key.arm_id},
        "outcome": outcome,
        "spans": public_spans,
        "budget": budget.public(),
        "usage": {
            "policy_version": USAGE_POLICY,
            "semantics": "cumulative_final_snapshot_counted_once",
            "first": first_usage,
            "final": final_usage,
            "accounted": accounted,
            "repair_delta": repair_delta,
            "repair_delta_status": repair_delta_status,
        },
        "tools": tool_accounting,
    }


def summarize_native_attempt_receipts(
    expected_keys: Sequence[AttemptKey], receipts: Sequence[Mapping[str, object]]
) -> dict[str, object]:
    """Validate the one-to-one row join and summarize usage and overlapping intervals."""
    expected = [key.validated() for key in expected_keys]
    if len(expected) != len(set(expected)):
        raise ValueError("expected receipt keys contain duplicates")
    rows: dict[AttemptKey, Mapping[str, object]] = {}
    intervals: list[tuple[int, int]] = []
    lane_milliseconds = 0
    outcomes: Counter[str] = Counter()
    usage_values: dict[str, list[int | None]] = {field: [] for field in USAGE_FIELDS}
    for receipt in receipts:
        _exact_keys(
            receipt,
            {"schema", "attempt", "outcome", "spans", "budget", "usage", "tools"},
            "native attempt receipt",
        )
        key = _validated_receipt_key(receipt)
        if key in rows:
            raise ValueError("native receipts contain a duplicate attempt key")
        rows[key] = receipt
        outcome = receipt.get("outcome")
        if outcome not in _OUTCOMES:
            raise ValueError("native receipt contains an invalid outcome")
        outcomes[str(outcome)] += 1
        usage = receipt.get("usage")
        if not isinstance(usage, Mapping):
            raise TypeError("native receipt usage must be an object")
        _exact_keys(
            usage,
            {
                "policy_version",
                "semantics",
                "first",
                "final",
                "accounted",
                "repair_delta",
                "repair_delta_status",
            },
            "native receipt usage",
        )
        if (
            usage.get("policy_version") != USAGE_POLICY
            or usage.get("semantics") != "cumulative_final_snapshot_counted_once"
        ):
            raise ValueError("native receipt usage policy is invalid")
        for name in ("first", "final", "accounted", "repair_delta"):
            values = usage[name]
            if not isinstance(values, Mapping) or set(values) != set(USAGE_FIELDS):
                raise ValueError(f"native receipt {name} usage fields are invalid")
            for field, value in values.items():
                if value is not None:
                    _nonnegative(value, f"{name} {field} usage")
        delta_status = usage["repair_delta_status"]
        if not isinstance(delta_status, Mapping) or set(delta_status) != set(USAGE_FIELDS):
            raise ValueError("native receipt repair delta statuses are invalid")
        if any(
            status not in {"not_applicable", "incomplete", "monotone", "nonmonotone"}
            for status in delta_status.values()
        ):
            raise ValueError("native receipt repair delta status is invalid")
        repair_delta = usage["repair_delta"]
        assert isinstance(repair_delta, Mapping)
        first_usage = usage["first"]
        final_usage = usage["final"]
        accounted_usage = usage["accounted"]
        assert isinstance(first_usage, Mapping)
        assert isinstance(final_usage, Mapping)
        assert isinstance(accounted_usage, Mapping)
        statuses = set(delta_status.values())
        if "not_applicable" in statuses and statuses != {"not_applicable"}:
            raise ValueError("native receipt mixes repair and non-repair usage statuses")
        for field in USAGE_FIELDS:
            status = delta_status[field]
            delta = repair_delta[field]
            first_value = first_usage[field]
            final_value = final_usage[field]
            accounted_value = accounted_usage[field]
            if status == "not_applicable":
                expected_delta = None
                expected_accounted = final_value
            elif first_value is None or final_value is None:
                if status != "incomplete":
                    raise ValueError("native receipt incomplete repair usage status is invalid")
                expected_delta = None
                expected_accounted = final_value
            elif final_value < first_value:
                if status != "nonmonotone":
                    raise ValueError("native receipt nonmonotone repair usage status is invalid")
                expected_delta = None
                expected_accounted = None
            else:
                if status != "monotone":
                    raise ValueError("native receipt monotone repair usage status is invalid")
                expected_delta = final_value - first_value
                expected_accounted = final_value
            if delta != expected_delta or accounted_value != expected_accounted:
                raise ValueError("native receipt usage accounting is inconsistent")
        accounted = usage.get("accounted")
        if not isinstance(accounted, Mapping) or set(accounted) != set(USAGE_FIELDS):
            raise ValueError("native receipt accounted usage fields are invalid")
        for field in USAGE_FIELDS:
            value = accounted[field]
            usage_values[field].append(
                None if value is None else _nonnegative(value, f"{field} usage")
            )
        public_spans = receipt.get("spans")
        if not isinstance(public_spans, list):
            raise TypeError("native receipt spans must be a list")
        observed_stages: set[str] = set()
        for span in public_spans:
            if not isinstance(span, Mapping) or set(span) != {
                "stage",
                "status",
                "start_offset_milliseconds",
                "end_offset_milliseconds",
                "duration_milliseconds",
            }:
                raise ValueError("native receipt span fields are invalid")
            validated_span = Span(
                stage=str(span["stage"]),
                status=span["status"],  # type: ignore[arg-type]
                start_offset_milliseconds=span["start_offset_milliseconds"],  # type: ignore[arg-type]
                end_offset_milliseconds=span["end_offset_milliseconds"],  # type: ignore[arg-type]
            ).public()
            if dict(span) != validated_span:
                raise ValueError("native receipt span is inconsistent")
            stage = str(span["stage"])
            if stage in observed_stages:
                raise ValueError("native receipt contains duplicate span stages")
            observed_stages.add(stage)
            duration = span["duration_milliseconds"]
            if duration is None:
                continue
            start = _nonnegative(span["start_offset_milliseconds"], "span start")
            end = _nonnegative(span["end_offset_milliseconds"], "span end")
            observed = _nonnegative(duration, "span duration")
            if end - start != observed:
                raise ValueError("native receipt span duration is inconsistent")
            lane_milliseconds += observed
            if end > start:
                intervals.append((start, end))
        _validate_budget_mapping(receipt.get("budget"))
        _validate_tools_mapping(receipt.get("tools"))
    if set(rows) != set(expected):
        raise ValueError("native receipt keys do not match the expected one-to-one join")

    wall_milliseconds = _interval_union(intervals)
    usage_summary: dict[str, object] = {}
    for field, values in usage_values.items():
        observed = [value for value in values if value is not None]
        missing = len(values) - len(observed)
        usage_summary[field] = {
            "total": sum(observed) if missing == 0 else None,
            "observed_total": sum(observed),
            "observed_attempt_count": len(observed),
            "missing_attempt_count": missing,
        }
    return {
        "schema": SUMMARY_RECEIPT_SCHEMA,
        "attempt_count": len(rows),
        "outcomes": {name: outcomes[name] for name in sorted(_OUTCOMES)},
        "usage": {"policy_version": USAGE_POLICY, "fields": usage_summary},
        "timing": {
            "origin": "benchmark_global_monotonic_t0",
            "lane_milliseconds": lane_milliseconds,
            "wall_active_milliseconds": wall_milliseconds,
            "concurrent_lane_milliseconds": lane_milliseconds - wall_milliseconds,
            "semantics": "relative intervals; lane time additive; wall time interval union",
        },
    }


def _usage_snapshot(event: Mapping[str, object] | None) -> dict[str, int | None]:
    source: Mapping[str, object] | None = None
    if isinstance(event, Mapping):
        for key in ("usage", "tokenUsage", "token_usage"):
            candidate = event.get(key)
            if isinstance(candidate, Mapping):
                source = candidate
                break
    snapshot: dict[str, int | None] = {}
    for field in USAGE_FIELDS:
        value: object = None
        if source is not None:
            value = next((source[name] for name in _USAGE_ALIASES[field] if name in source), None)
        snapshot[field] = value if type(value) is int and 0 <= value <= 2**63 - 1 else None
    return snapshot


def _tool_accounting(
    first_calls: Sequence[Mapping[str, object]],
    repair_calls: Sequence[Mapping[str, object]],
    cumulative_calls: Sequence[Mapping[str, object]],
) -> dict[str, object]:
    stages: Counter[str] = Counter()
    observed_success_milliseconds = 0
    observed_success_calls = 0
    missing_success_calls = 0
    for call in cumulative_calls:
        stage = _call_stage(call)
        stages[stage] += 1
        if stage != "successful":
            continue
        duration = call.get("duration_milliseconds")
        if type(duration) is int and 0 <= duration <= 2**63 - 1:
            observed_success_calls += 1
            observed_success_milliseconds += duration
        else:
            missing_success_calls += 1

    pending: dict[str, deque[None]] = {}
    eligible = 0
    for call in first_calls:
        if _call_stage(call) != "arguments":
            continue
        eligible += 1
        pending.setdefault(_call_tool(call), deque()).append(None)
    closures = 0
    repair_successful_calls = 0
    for call in repair_calls:
        if _call_stage(call) != "successful":
            continue
        repair_successful_calls += 1
        failures = pending.get(_call_tool(call))
        if failures:
            failures.popleft()
            closures += 1

    stage_counts = {
        stage: stages[stage]
        for stage in ("successful", "arguments", "execution", "result", "untyped")
    }
    if sum(stage_counts.values()) != len(cumulative_calls):
        raise ValueError("tool-call stage counts do not reconcile")
    return {
        "counts": {
            "first_turn": len(first_calls),
            "repair_turn": len(repair_calls),
            "cumulative": len(cumulative_calls),
            "by_stage": stage_counts,
        },
        "argument_repair": {
            "eligible_failures": eligible,
            "repair_successful_calls": repair_successful_calls,
            "closures": closures,
            "unclosed": eligible - closures,
            "semantics": "fifo_one_success_closes_one_prior_same_tool_arguments_failure",
        },
        "successful_call_timing": {
            "observed_call_count": observed_success_calls,
            "missing_call_count": missing_success_calls,
            "observed_total_milliseconds": observed_success_milliseconds,
            "total_milliseconds": (
                observed_success_milliseconds if missing_success_calls == 0 else None
            ),
        },
    }


def _call_stage(call: Mapping[str, object]) -> str:
    success = call.get("success")
    if success is True:
        return "successful"
    if success is not False:
        return "untyped"
    observation = call.get("host_observation")
    facts = getattr(observation, "facts", None)
    if facts is None and isinstance(observation, Mapping):
        facts = observation.get("facts")
    stage = facts.get("failure_stage") if isinstance(facts, Mapping) else None
    return str(stage) if stage in _FAILURE_STAGES else "untyped"


def _call_tool(call: Mapping[str, object]) -> str:
    observation = call.get("host_observation")
    tool = getattr(observation, "tool", None)
    if not isinstance(tool, str):
        tool = call.get("name")
    return tool if isinstance(tool, str) and _TOOL_ID.fullmatch(tool) else "unknown_tool"


def _validated_receipt_key(receipt: Mapping[str, object]) -> AttemptKey:
    if receipt.get("schema") != ATTEMPT_RECEIPT_SCHEMA:
        raise ValueError("native attempt receipt schema is invalid")
    attempt = receipt.get("attempt")
    if not isinstance(attempt, Mapping) or set(attempt) != {"task_id", "arm_id"}:
        raise ValueError("native receipt attempt identity is invalid")
    task_id = attempt["task_id"]
    arm_id = attempt["arm_id"]
    if not isinstance(task_id, str) or not isinstance(arm_id, str):
        raise TypeError("native receipt attempt identities must be strings")
    return AttemptKey(task_id, arm_id).validated()


def _validate_budget_mapping(value: object) -> None:
    if not isinstance(value, Mapping):
        raise TypeError("native receipt budget must be an object")
    _exact_keys(
        value,
        {
            "configured_milliseconds",
            "granted_milliseconds",
            "remaining_after_first_milliseconds",
            "remaining_terminal_milliseconds",
        },
        "native receipt budget",
    )
    Budget(
        configured_milliseconds=value["configured_milliseconds"],  # type: ignore[arg-type]
        granted_milliseconds=value["granted_milliseconds"],  # type: ignore[arg-type]
        remaining_after_first_milliseconds=value["remaining_after_first_milliseconds"],  # type: ignore[arg-type]
        remaining_terminal_milliseconds=value["remaining_terminal_milliseconds"],  # type: ignore[arg-type]
    ).public()


def _validate_tools_mapping(value: object) -> None:
    if not isinstance(value, Mapping):
        raise TypeError("native receipt tools must be an object")
    _exact_keys(
        value,
        {"counts", "argument_repair", "successful_call_timing"},
        "native receipt tools",
    )
    counts = value["counts"]
    repair = value["argument_repair"]
    timing = value["successful_call_timing"]
    if not all(isinstance(item, Mapping) for item in (counts, repair, timing)):
        raise TypeError("native receipt tool sections must be objects")
    assert isinstance(counts, Mapping)
    assert isinstance(repair, Mapping)
    assert isinstance(timing, Mapping)
    _exact_keys(
        counts,
        {"first_turn", "repair_turn", "cumulative", "by_stage"},
        "native receipt tool counts",
    )
    stages = counts["by_stage"]
    if not isinstance(stages, Mapping) or set(stages) != {
        "successful",
        "arguments",
        "execution",
        "result",
        "untyped",
    }:
        raise ValueError("native receipt tool stages are invalid")
    numeric_counts = [counts[name] for name in ("first_turn", "repair_turn", "cumulative")]
    numeric_counts.extend(stages.values())
    if any(type(item) is not int or item < 0 for item in numeric_counts):
        raise TypeError("native receipt tool counts must be nonnegative integers")
    if counts["cumulative"] != counts["first_turn"] + counts["repair_turn"]:
        raise ValueError("native receipt turn call counts do not reconcile")
    if counts["cumulative"] != sum(stages.values()):
        raise ValueError("native receipt stage call counts do not reconcile")
    _exact_keys(
        repair,
        {
            "eligible_failures",
            "repair_successful_calls",
            "closures",
            "unclosed",
            "semantics",
        },
        "native receipt argument repair",
    )
    if repair["semantics"] != "fifo_one_success_closes_one_prior_same_tool_arguments_failure":
        raise ValueError("native receipt argument repair semantics are invalid")
    eligible = _nonnegative(repair["eligible_failures"], "eligible argument failures")
    repair_successful = _nonnegative(repair["repair_successful_calls"], "successful repair calls")
    closures = _nonnegative(repair["closures"], "argument repair closures")
    unclosed = _nonnegative(repair["unclosed"], "unclosed argument failures")
    if closures + unclosed != eligible:
        raise ValueError("native receipt argument repair counts do not reconcile")
    if repair_successful > counts["repair_turn"] or repair_successful > stages["successful"]:
        raise ValueError("native receipt successful repair calls do not reconcile")
    if closures > eligible or closures > repair_successful:
        raise ValueError("native receipt argument repair closures exceed eligible successes")
    _exact_keys(
        timing,
        {
            "observed_call_count",
            "missing_call_count",
            "observed_total_milliseconds",
            "total_milliseconds",
        },
        "native receipt successful timing",
    )
    observed_calls = _nonnegative(timing["observed_call_count"], "observed successful calls")
    missing = _nonnegative(timing["missing_call_count"], "missing successful calls")
    observed = _nonnegative(
        timing["observed_total_milliseconds"], "observed successful milliseconds"
    )
    total = timing["total_milliseconds"]
    if observed_calls + missing != stages["successful"]:
        raise ValueError("native receipt successful timing call counts do not reconcile")
    if total is not None:
        _nonnegative(total, "total successful milliseconds")
    if missing == 0 and total != observed or missing > 0 and total is not None:
        raise ValueError("native receipt successful timing missingness is inconsistent")


def _exact_keys(source: Mapping[str, object], expected: set[str], name: str) -> None:
    actual = set(source)
    if actual != expected:
        raise ValueError(
            f"{name} fields differ: missing={sorted(expected - actual)}, "
            f"extra={sorted(actual - expected)}"
        )


def _interval_union(intervals: Sequence[tuple[int, int]]) -> int:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(intervals):
        if not merged or start > merged[-1][1]:
            merged.append((start, end))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
    return sum(end - start for start, end in merged)


def _nonnegative(value: object, name: str) -> int:
    if type(value) is not int or value < 0:
        raise TypeError(f"{name} must be a nonnegative integer")
    return value


def _optional_nonnegative(value: object, name: str) -> int | None:
    return None if value is None else _nonnegative(value, name)


__all__ = [
    "ATTEMPT_RECEIPT_SCHEMA",
    "SUMMARY_RECEIPT_SCHEMA",
    "AttemptKey",
    "Budget",
    "Span",
    "build_native_attempt_receipt",
    "summarize_native_attempt_receipts",
]
