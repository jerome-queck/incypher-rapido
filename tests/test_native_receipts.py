from __future__ import annotations

import json

import pytest

from rapido.evidence import HostObservation
from rapido.native_receipts import (
    ATTEMPT_RECEIPT_SCHEMA,
    SUMMARY_RECEIPT_SCHEMA,
    AttemptKey,
    Budget,
    Span,
    build_native_attempt_receipt,
    summarize_native_attempt_receipts,
)
from rapido.offline_h24 import CATALOGUE
from rapido.reporting import USAGE_FIELDS, USAGE_POLICY


def _failed(tool: str, stage: str) -> dict[str, object]:
    return {
        "name": tool,
        "success": False,
        "arguments": {"private_value": "INCYPHER{must_not_escape}"},
        "host_observation": HostObservation(
            tool=tool,
            success=False,
            source_bound=True,
            facts={"failure_stage": stage, "constraint": "type"},
        ),
    }


def _success(tool: str, duration: int | None = 7) -> dict[str, object]:
    call: dict[str, object] = {
        "name": tool,
        "success": True,
        "host_observation": HostObservation(
            tool=tool,
            success=True,
            source_bound=True,
        ),
        "candidate_sha256s": ["f" * 64],
    }
    if duration is not None:
        call["duration_milliseconds"] = duration
    return call


def _receipt(
    key: AttemptKey,
    *,
    start: int = 0,
    end: int = 10,
    outcome: str = "completed",
    first_event: dict[str, object] | None = None,
    final_event: dict[str, object] | None = None,
    first_calls: list[dict[str, object]] | None = None,
    repair_calls: list[dict[str, object]] | None = None,
    repair_attempted: bool = False,
) -> dict[str, object]:
    first_calls = [] if first_calls is None else first_calls
    repair_calls = [] if repair_calls is None else repair_calls
    return build_native_attempt_receipt(
        key=key,
        outcome=outcome,  # type: ignore[arg-type]
        spans=(Span("first_turn", "completed", start, end),),
        budget=Budget(300_000, 240_000, 200_000, 190_000),
        first_event=first_event,
        final_event=final_event,
        first_turn_calls=first_calls,
        repair_turn_calls=repair_calls,
        cumulative_calls=first_calls + repair_calls,
        repair_attempted=repair_attempted,
    )


def test_cumulative_final_usage_is_counted_once_and_delta_is_fieldwise() -> None:
    receipt = _receipt(
        AttemptKey("h24-easy-01", "evidence_repair"),
        first_event={
            "usage": {
                "inputTokens": 10,
                "outputTokens": 2,
                "cachedInputTokens": 4,
                "reasoningOutputTokens": 6,
                "totalTokens": 22,
            }
        },
        final_event={
            "token_usage": {
                "input_tokens": 17,
                "output_tokens": 5,
                "cached_input_tokens": 4,
                "reasoning_tokens": 9,
                "total_tokens": 35,
            }
        },
        repair_attempted=True,
    )

    usage = receipt["usage"]
    assert isinstance(usage, dict)
    assert usage["policy_version"] == USAGE_POLICY
    assert usage["accounted"] == {
        "input_tokens": 17,
        "output_tokens": 5,
        "cached_input_tokens": 4,
        "reasoning_tokens": 9,
    }
    assert usage["repair_delta"] == {
        "input_tokens": 7,
        "output_tokens": 3,
        "cached_input_tokens": 0,
        "reasoning_tokens": 3,
    }
    assert usage["repair_delta_status"] == dict.fromkeys(USAGE_FIELDS, "monotone")
    assert "total_tokens" not in json.dumps(receipt)


def test_missing_and_nonmonotone_usage_remain_null() -> None:
    receipt = _receipt(
        AttemptKey("h24-medium-01", "evidence_repair"),
        first_event={"usage": {"inputTokens": 10, "outputTokens": 3}},
        final_event={"usage": {"inputTokens": 9, "cachedInputTokens": -1}},
        repair_attempted=True,
    )
    usage = receipt["usage"]
    assert isinstance(usage, dict)
    assert usage["accounted"] == {
        "input_tokens": None,
        "output_tokens": None,
        "cached_input_tokens": None,
        "reasoning_tokens": None,
    }
    assert usage["repair_delta"] == dict.fromkeys(USAGE_FIELDS)
    assert usage["repair_delta_status"] == {
        "input_tokens": "nonmonotone",
        "output_tokens": "incomplete",
        "cached_input_tokens": "incomplete",
        "reasoning_tokens": "incomplete",
    }


def test_fifo_same_tool_argument_failure_closure_and_call_reconciliation() -> None:
    first = [
        _failed("inspect_artifact", "arguments"),
        _failed("inspect_artifact", "arguments"),
        _failed("read_text", "execution"),
    ]
    repair = [_success("inspect_artifact", 11), _success("read_text", None)]
    receipt = _receipt(
        AttemptKey("h24-hard-01", "evidence_repair"),
        first_calls=first,
        repair_calls=repair,
        repair_attempted=True,
    )

    tools = receipt["tools"]
    assert isinstance(tools, dict)
    assert tools["counts"] == {
        "first_turn": 3,
        "repair_turn": 2,
        "cumulative": 5,
        "by_stage": {
            "successful": 2,
            "arguments": 2,
            "execution": 1,
            "result": 0,
            "untyped": 0,
        },
    }
    assert tools["argument_repair"] == {
        "eligible_failures": 2,
        "repair_successful_calls": 2,
        "closures": 1,
        "unclosed": 1,
        "semantics": "fifo_one_success_closes_one_prior_same_tool_arguments_failure",
    }
    assert tools["successful_call_timing"] == {
        "observed_call_count": 1,
        "missing_call_count": 1,
        "observed_total_milliseconds": 11,
        "total_milliseconds": None,
    }

    with pytest.raises(ValueError, match="does not reconcile"):
        build_native_attempt_receipt(
            key=AttemptKey("h24-hard-01", "evidence_repair"),
            outcome="completed",
            spans=(),
            budget=Budget(10, 10, 5, 4),
            first_event=None,
            final_event=None,
            first_turn_calls=first,
            repair_turn_calls=repair,
            cumulative_calls=first,
            repair_attempted=True,
        )


def test_summary_rejects_impossible_repair_closures_and_success_timing_counts() -> None:
    key = AttemptKey("h24-hard-02", "evidence_repair")
    receipt = _receipt(
        key,
        first_calls=[
            _failed("inspect_artifact", "arguments"),
            _failed("inspect_artifact", "arguments"),
        ],
        repair_calls=[_success("inspect_artifact", 9)],
        repair_attempted=True,
    )

    impossible_closures = json.loads(json.dumps(receipt))
    repair = impossible_closures["tools"]["argument_repair"]
    repair["closures"] = 2
    repair["unclosed"] = 0
    with pytest.raises(ValueError, match="closures exceed"):
        summarize_native_attempt_receipts((key,), (impossible_closures,))

    impossible_timing = json.loads(json.dumps(receipt))
    timing = impossible_timing["tools"]["successful_call_timing"]
    timing["observed_call_count"] = 0
    with pytest.raises(ValueError, match="timing call counts"):
        summarize_native_attempt_receipts((key,), (impossible_timing,))

    zero_duration = _receipt(
        key,
        repair_calls=[_success("inspect_artifact", 0)],
        repair_attempted=True,
    )
    boolean_total = json.loads(json.dumps(zero_duration))
    boolean_total["tools"]["successful_call_timing"]["total_milliseconds"] = False
    with pytest.raises(TypeError, match="nonnegative integer"):
        summarize_native_attempt_receipts((key,), (boolean_total,))


def test_summary_requires_one_to_one_keys_and_unions_overlapping_intervals() -> None:
    keys = (AttemptKey("h24-easy-01", "a"), AttemptKey("h24-easy-01", "b"))
    first = _receipt(
        keys[0],
        start=0,
        end=10,
        final_event={"usage": {"inputTokens": 3}},
    )
    second = _receipt(keys[1], start=5, end=15)
    summary = summarize_native_attempt_receipts(keys, (first, second))

    assert summary["schema"] == SUMMARY_RECEIPT_SCHEMA
    assert summary["attempt_count"] == 2
    assert summary["timing"] == {
        "origin": "benchmark_global_monotonic_t0",
        "lane_milliseconds": 20,
        "wall_active_milliseconds": 15,
        "concurrent_lane_milliseconds": 5,
        "semantics": "relative intervals; lane time additive; wall time interval union",
    }
    usage = summary["usage"]
    assert isinstance(usage, dict)
    fields = usage["fields"]
    assert isinstance(fields, dict)
    assert fields["input_tokens"] == {
        "total": None,
        "observed_total": 3,
        "observed_attempt_count": 1,
        "missing_attempt_count": 1,
    }
    with pytest.raises(ValueError, match="one-to-one"):
        summarize_native_attempt_receipts(keys, (first,))
    with pytest.raises(ValueError, match="duplicate"):
        summarize_native_attempt_receipts(keys, (first, first))
    injected = dict(first)
    injected["secret_value"] = "credential_value"
    with pytest.raises(ValueError, match="extra=.*secret_value"):
        summarize_native_attempt_receipts((keys[0],), (injected,))
    mutated = json.loads(json.dumps(first))
    mutated["usage"]["accounted"]["input_tokens"] = 99
    with pytest.raises(ValueError, match="usage accounting"):
        summarize_native_attempt_receipts((keys[0],), (mutated,))
    wrong_identity = json.loads(json.dumps(first))
    wrong_identity["attempt"]["task_id"] = 1
    with pytest.raises(TypeError, match="must be strings"):
        summarize_native_attempt_receipts((keys[0],), (wrong_identity,))
    duplicate_span = json.loads(json.dumps(first))
    duplicate_span["spans"].append(dict(duplicate_span["spans"][0]))
    with pytest.raises(ValueError, match="duplicate span"):
        summarize_native_attempt_receipts((keys[0],), (duplicate_span,))


@pytest.mark.parametrize("outcome", ["provider_failure", "cancelled", "inconclusive"])
def test_terminal_failures_still_emit_complete_nullable_receipts(outcome: str) -> None:
    receipt = _receipt(
        AttemptKey(f"task-{outcome}", "one_shot"),
        outcome=outcome,
        first_event=None,
        final_event=None,
    )
    assert receipt["schema"] == ATTEMPT_RECEIPT_SCHEMA
    usage = receipt["usage"]
    assert isinstance(usage, dict)
    assert usage["accounted"] == dict.fromkeys(USAGE_FIELDS)
    assert set(receipt) == {
        "schema",
        "attempt",
        "outcome",
        "spans",
        "budget",
        "usage",
        "tools",
    }


def test_budget_and_span_domains_fail_closed() -> None:
    with pytest.raises(ValueError, match="exceeds"):
        Budget(10, 11, None, None).public()
    with pytest.raises(ValueError, match="increased"):
        Budget(10, 10, 4, 5).public()
    with pytest.raises(ValueError, match="not-run"):
        Span("cleanup", "not_run", 0, 0).public()
    with pytest.raises(ValueError, match="identity"):
        AttemptKey("/private/task", "one_shot").validated()


def test_receipt_drops_raw_candidates_arguments_paths_authorities_and_digests() -> None:
    secret = "INCYPHER{must_not_escape}"
    receipt = _receipt(
        AttemptKey("h24-ai-01", "one_shot"),
        first_event={
            "usage": {
                "inputTokens": 1,
                "api_key": "credential_value",
                "private_oracle_key": secret,
            },
            "model_prose": secret,
            "path": "/private/workspace",
            "authority": "https://target.invalid",
        },
        final_event={"usage": {"inputTokens": 1}},
        first_calls=[_success("read_text")],
    )
    encoded = json.dumps(receipt, sort_keys=True)
    for forbidden in (
        secret,
        "credential_value",
        "private_oracle_key",
        "/private/workspace",
        "target.invalid",
        "f" * 64,
        "private_value",
    ):
        assert forbidden not in encoded


def test_all_h24_task_arm_identities_include_non_success_terminal_rows() -> None:
    outcomes = ("completed", "provider_failure", "cancelled", "inconclusive", "timeout")
    keys = [AttemptKey(task.id, arm) for task in CATALOGUE for arm in ("one_shot", "repair")]
    receipts = [
        _receipt(
            key,
            start=index,
            end=index + 1,
            outcome=outcomes[index % len(outcomes)],
        )
        for index, key in enumerate(keys)
    ]
    summary = summarize_native_attempt_receipts(keys, receipts)
    assert summary["attempt_count"] == 48
    assert sum(summary["outcomes"].values()) == 48
    assert all(summary["outcomes"][outcome] > 0 for outcome in outcomes)
