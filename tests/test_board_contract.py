from __future__ import annotations

import asyncio
import copy
import json
import os
import socket
from pathlib import Path
from unittest import mock

import pytest

from rapido.board_contract import (
    CONTRACT_SCHEMA,
    SCENARIO_IDS,
    run_contract,
    validate_public_receipt,
)
from rapido.clock import ManualClock, SystemClock


def test_accelerated_contract_covers_exact_ten_scenarios_without_sockets(
    tmp_path: Path,
) -> None:
    seed = b"private-contract-seed".ljust(32, b"-")
    with mock.patch.object(socket, "create_connection", side_effect=AssertionError("socket used")):
        receipt = asyncio.run(
            run_contract(
                tmp_path,
                private_seed=seed,
                clock=ManualClock(),
                soak_seconds=19_800,
            )
        ).public()
    assert receipt["schema"] == CONTRACT_SCHEMA
    assert receipt["clock_mode"] == "accelerated"
    assert receipt["scenario_count"] == receipt["passed_count"] == 10
    assert receipt["correctness_denominator_included"] is False
    assert tuple(row["scenario_id"] for row in receipt["scenarios"]) == SCENARIO_IDS
    assert all(row["passed"] is True for row in receipt["scenarios"])
    encoded = json.dumps(receipt, sort_keys=True)
    assert "private-contract-seed" not in encoded
    assert "INCYPHER{" not in encoded
    assert "https://" not in encoded
    assert str(tmp_path) not in encoded


def test_contract_scenario_facts_preserve_required_boundaries(tmp_path: Path) -> None:
    receipt = asyncio.run(
        run_contract(
            tmp_path,
            private_seed=os.urandom(32),
            clock=ManualClock(100),
            soak_seconds=330,
        )
    ).public()
    rows = {row["scenario_id"]: row["facts"] for row in receipt["scenarios"]}
    assert rows["distinct_submission_outcomes"] == {
        "correct": True,
        "incorrect": True,
        "historical": True,
        "historical_not_current": True,
    }
    assert rows["ambiguous_write_reconciled_once"] == {
        "writes": 1,
        "reconciled": True,
        "second_write": False,
    }
    assert rows["transient_read_and_permanent_auth"] == {
        "transient_recovered": True,
        "auth_http_status": 401,
        "auth_error": "board_http_401",
        "attempt_delta": 0,
    }
    assert rows["queued_job_unstarted"] == {
        "queued_jobs": 1,
        "started_jobs": 0,
        "attempt_count": 0,
        "submission_count": 0,
        "solve_count": 0,
        "current_verification_count": 0,
    }
    assert rows["fresh_generation_exact_answer"] == {
        "fresh_generation": True,
        "exact_match": True,
        "current_verification_count": 1,
        "current_generation_match": True,
    }
    assert rows["different_answer_separate_axes"] == {
        "exact_match": False,
        "current_verification_count": 0,
        "old_value_current": False,
        "new_value_current": False,
        "method_oracle_match": True,
        "method_axis": "synthetic_only",
    }
    assert rows["changed_bytes_reset_context"] == {
        "refreshed": True,
        "context_advanced": True,
        "same_reference": True,
        "material_changed": True,
        "memory_record_count": 0,
        "prompt_memory_count": 0,
        "old_private_excluded": True,
    }
    assert rows["watch_change_original_deadline"]["deadline_unchanged"] is True
    assert rows["watch_change_original_deadline"]["transient_offset_seconds"] > 0
    assert rows["watch_change_original_deadline"]["change_offset_seconds"] > 0
    assert rows["deadline_cancel_cleanup"] == {
        "status": "deadline",
        "active_jobs": 0,
        "queued_jobs": 0,
        "pending_writes": 0,
        "owned_instances": 0,
        "workspace_entries": 0,
        "instance_creates": 1,
        "instance_deletes": 1,
        "runtime_cancelled": True,
        "runtime_closed": True,
    }
    assert rows["serialized_startup_independent_turns"] == {
        "startup_peak": 1,
        "turn_peak": 2,
        "pilot_result_rows": 24,
        "diagnostics_redacted": True,
        "startup_contract": "pr71_serialized",
        "diagnostics_contract": "pr70_closed_labels",
    }


def test_short_real_clock_smoke_is_separately_labelled(tmp_path: Path) -> None:
    receipt = asyncio.run(
        run_contract(
            tmp_path,
            private_seed=os.urandom(32),
            clock=SystemClock(),
            soak_seconds=2.0,
        )
    ).public()
    assert receipt["clock_mode"] == "real"
    assert receipt["requested_seconds"] == 2.0
    assert receipt["passed"] is True
    watch = next(
        row
        for row in receipt["scenarios"]
        if row["scenario_id"] == "watch_change_original_deadline"
    )
    assert watch["facts"]["deadline_seconds"] == 2.0


@pytest.fixture
def valid_receipt(tmp_path: Path) -> dict[str, object]:
    return asyncio.run(
        run_contract(
            tmp_path,
            private_seed=os.urandom(32),
            clock=ManualClock(),
            soak_seconds=30,
        )
    ).public()


def test_public_receipt_accepts_all_ten_recomputed_semantic_passes(
    valid_receipt: dict[str, object],
) -> None:
    validate_public_receipt(valid_receipt)
    assert valid_receipt["passed_count"] == len(SCENARIO_IDS)


@pytest.mark.parametrize(
    ("scenario_id", "field", "failed_value"),
    [
        (SCENARIO_IDS[0], "correct", False),
        (SCENARIO_IDS[1], "second_write", True),
        (SCENARIO_IDS[2], "attempt_delta", 1),
        (SCENARIO_IDS[3], "started_jobs", 1),
        (SCENARIO_IDS[4], "current_verification_count", 0),
        (SCENARIO_IDS[5], "method_oracle_match", False),
        (SCENARIO_IDS[6], "memory_record_count", 1),
        (SCENARIO_IDS[7], "deadline_unchanged", False),
        (SCENARIO_IDS[8], "owned_instances", 100),
        (SCENARIO_IDS[9], "turn_peak", 1),
    ],
)
def test_public_receipt_rejects_true_pass_bits_for_failed_scenario_facts(
    valid_receipt: dict[str, object],
    scenario_id: str,
    field: str,
    failed_value: object,
) -> None:
    receipt = copy.deepcopy(valid_receipt)
    scenarios = receipt["scenarios"]
    assert isinstance(scenarios, list)
    row = scenarios[SCENARIO_IDS.index(scenario_id)]
    row["facts"][field] = failed_value

    with pytest.raises(ValueError, match="pass bit contradicts"):
        validate_public_receipt(receipt)


def test_public_receipt_rejects_false_pass_bit_for_passing_facts(
    valid_receipt: dict[str, object],
) -> None:
    receipt = copy.deepcopy(valid_receipt)
    scenarios = receipt["scenarios"]
    assert isinstance(scenarios, list)
    scenarios[0]["passed"] = False
    receipt["passed_count"] = 9
    receipt["passed"] = False

    with pytest.raises(ValueError, match="pass bit contradicts"):
        validate_public_receipt(receipt)


@pytest.mark.parametrize("field", ["credential", "api_key", "private_value"])
def test_public_receipt_rejects_unallowlisted_top_level_fields(
    valid_receipt: dict[str, object], field: str
) -> None:
    receipt = copy.deepcopy(valid_receipt)
    receipt[field] = "redacted"
    with pytest.raises(ValueError, match="unexpected top-level"):
        validate_public_receipt(receipt)


@pytest.mark.parametrize(
    "value",
    [
        "INCYPHER{private}",
        "https://example.invalid/private",
        "/private/location",
        r"C:\private\location",
        r"\\server\share\private",
        "//server/share/private",
        "a" * 64,
        "authority.example:443",
    ],
)
def test_public_receipt_rejects_private_values_paths_and_authorities(
    valid_receipt: dict[str, object], value: str
) -> None:
    receipt = copy.deepcopy(valid_receipt)
    scenarios = receipt["scenarios"]
    assert isinstance(scenarios, list)
    scenarios[2]["facts"]["auth_error"] = value
    with pytest.raises(ValueError, match="forbidden"):
        validate_public_receipt(receipt)


@pytest.mark.parametrize(
    "value",
    ["credential_value", "private_oracle_key", "secret_value", "api_key"],
)
def test_public_receipt_rejects_out_of_domain_secret_like_allowed_values(
    valid_receipt: dict[str, object], value: str
) -> None:
    receipt = copy.deepcopy(valid_receipt)
    scenarios = receipt["scenarios"]
    assert isinstance(scenarios, list)
    scenarios[2]["facts"]["auth_error"] = value
    with pytest.raises(ValueError, match="outside its field domain"):
        validate_public_receipt(receipt)


def test_public_receipt_rejects_unallowlisted_scenario_facts(
    valid_receipt: dict[str, object],
) -> None:
    receipt = copy.deepcopy(valid_receipt)
    scenarios = receipt["scenarios"]
    assert isinstance(scenarios, list)
    scenarios[0]["facts"]["credential"] = "redacted"
    with pytest.raises(ValueError, match="not allowlisted"):
        validate_public_receipt(receipt)


def test_manual_clock_advances_cooperatively_and_rejects_backwards_time() -> None:
    clock = ManualClock(5)
    asyncio.run(clock.sleep(2.5))
    clock.advance(0.5)
    assert clock.monotonic() == 8
    assert clock.sleeps == [2.5]
    with pytest.raises(ValueError, match="non-negative"):
        asyncio.run(clock.sleep(-1))
    with pytest.raises(ValueError, match="non-negative"):
        clock.advance(-1)


def test_contract_rejects_invalid_private_seed_and_duration(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="32..1024"):
        asyncio.run(run_contract(tmp_path, private_seed=b"short"))
    with pytest.raises(ValueError, match="19800"):
        asyncio.run(run_contract(tmp_path, private_seed=os.urandom(32), soak_seconds=19_801))


@pytest.mark.parametrize(
    ("initial", "origin", "deadline", "message"),
    [
        (10.0, 10.0, None, "supplied together"),
        (10.0, 10.0, 41.0, "does not match"),
        (9.999, 10.0, 40.0, "moved before"),
        (40.0, 10.0, 40.0, "already stale"),
    ],
)
def test_contract_rejects_invalid_absolute_soak_windows(
    tmp_path: Path,
    initial: float,
    origin: float,
    deadline: float | None,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        asyncio.run(
            run_contract(
                tmp_path,
                private_seed=os.urandom(32),
                clock=ManualClock(initial),
                soak_seconds=30,
                absolute_origin=origin,
                absolute_deadline=deadline,
            )
        )
