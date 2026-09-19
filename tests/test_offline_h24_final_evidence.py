"""Regression checks for the committed sanitized H24 evidence package."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from rapido.offline_h24_evaluation import evaluate_h24_receipt

ROOT = Path(__file__).resolve().parents[1]
NOTES = ROOT / "notes" / "research"


def _load(name: str) -> dict[str, Any]:
    value = json.loads((NOTES / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _keys(value: object) -> set[str]:
    if isinstance(value, Mapping):
        return {str(key) for key in value} | {
            nested for item in value.values() for nested in _keys(item)
        }
    if isinstance(value, list):
        return {nested for item in value for nested in _keys(item)}
    return set()


def test_committed_h24_evidence_replays_and_remains_sanitized() -> None:
    preregistration = _load("offline-h24-preregistration-v1.json")
    receipt = _load("offline-h24-attempt-v5-evaluation-receipt-2026-09-19.json")
    evaluation = _load("offline-h24-attempt-v5-evaluation-result-2026-09-19.json")

    recomputed = evaluate_h24_receipt(preregistration, receipt)
    assert recomputed == evaluation
    assert (
        NOTES.joinpath("offline-h24-attempt-v5-evaluation-result-2026-09-19.json").read_text(
            encoding="utf-8"
        )
        == json.dumps(recomputed, sort_keys=True, separators=(",", ":")) + "\n"
    )
    assert set(receipt) == {
        "barrier",
        "cleanup",
        "fixture_preflight",
        "outcomes",
        "preregistration_sha256",
        "registration",
        "run_started_at_utc",
        "runtime_descriptor_preflight",
        "runtime_resources",
        "runtime_spans",
        "schema",
        "scoring_elapsed_milliseconds",
        "soak",
    }
    assert set(evaluation) == {
        "checkpoints",
        "counts",
        "decision",
        "diagnostics",
        "gates",
        "schema",
        "timing",
        "usage",
    }
    assert len(receipt["outcomes"]) == 48
    assert {
        arm: sum(row["arm"] == arm for row in receipt["outcomes"])
        for arm in ("one_shot", "evidence_repair")
    } == {"one_shot": 24, "evidence_repair": 24}
    assert receipt["soak"]["scenario_count"] == 10
    assert receipt["soak"]["passed_count"] == 10
    assert all(row["passed"] is True for row in receipt["soak"]["scenarios"])

    assert evaluation["decision"] == "no_justified_change"
    assert evaluation["counts"]["one_shot"]["C"] == 24
    assert evaluation["counts"]["one_shot"]["Q"] == 11
    assert evaluation["counts"]["evidence_repair"]["C"] == 24
    assert evaluation["counts"]["evidence_repair"]["Q"] == 12
    assert evaluation["gates"]["easy_non_regression"]["passed"] is False
    assert evaluation["gates"]["cleanup_and_privacy"] is False
    assert evaluation["diagnostics"]["automatic_production_promotion"] is False

    forbidden = set(preregistration["privacy"]["forbidden"])
    for artifact in (receipt, evaluation):
        assert forbidden.isdisjoint(_keys(artifact))
        encoded = json.dumps(artifact, sort_keys=True)
        assert "/Users/" not in encoded
        assert "/Volumes/" not in encoded
        assert "file://" not in encoded
        assert "http://" not in encoded
        assert "https://" not in encoded
