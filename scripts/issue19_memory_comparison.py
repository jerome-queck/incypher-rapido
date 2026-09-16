#!/usr/bin/env python3
"""Run the frozen, deterministic, effect-free issue #19 M1 comparison."""

from __future__ import annotations

import _socket
import argparse
import base64
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import unicodedata
import urllib.parse
from collections.abc import Mapping, Sequence
from contextlib import AbstractContextManager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from rapido.board import Challenge
from rapido.memory import (
    MEMORY_ARMS,
    PROJECTION_BYTES,
    PROTOCOL_SHA256,
    PUBLIC_RECORD_FIELDS,
    AnalysisClaim,
    CandidateContext,
    CandidateEvidence,
    CandidateMemoryAggregate,
    CandidateVerification,
    FailureRecord,
    HostObservation,
    MemoryProjection,
    MemoryTarget,
    PublicMemoryRecord,
    TacticOutcome,
    canonical_bytes,
    project_memory,
    record_order,
    repeated_fingerprint,
    sanitize_public_value,
)
from rapido.routing import RouteSpec
from rapido.solver import MAX_AGENT_MESSAGE_BYTES, build_turn_prompt

EXPECTED_PROTOCOL_SHA256 = "4605399b8ff84acef4ecbcd30bd1856a86b8e3792d94f03fd525db4d70cd8a6e"
DEFAULT_PROTOCOL_PATH = ROOT / "notes/research/issue-19-memory-comparison-protocol-v1.json"
DEFAULT_RESULT_PATH = ROOT / "notes/research/issue-19-memory-comparison-v1.json"
COMMAND_ADDENDUM_PATH = ROOT / "notes/research/issue-19-memory-comparison-command-addendum-v1.json"
EXPECTED_COMMAND_ADDENDUM_SHA256 = (
    "756b1e5f0d0b29e1db88db516b9787e6cf70b85d96c99f8bac01786e919da740"
)
FROZEN_PROTOCOL_COMMAND = (
    "python scripts/issue19_memory_comparison.py "
    "--protocol notes/research/issue-19-memory-comparison-protocol-v1.json "
    "--output notes/research/issue-19-memory-comparison-v1.json"
)
REGISTERED_COMMAND = (
    ".venv/bin/python scripts/issue19_memory_comparison.py "
    "--protocol notes/research/issue-19-memory-comparison-protocol-v1.json "
    "--output notes/research/issue-19-memory-comparison-v1.json"
)
EFFECT_FIELDS = (
    "board",
    "containers",
    "instances",
    "model_inference",
    "network",
    "submissions",
    "targets",
)
PERMUTATIONS = ("declared", "reverse", "rotate_left_one", "even_then_odd")
RAW_FIELDS = (
    "case_id",
    "arm_id",
    "permutation",
    "visible_record_ids",
    "visible_kind_counts",
    "useful_record_count",
    "repeated_fingerprint_count",
    "deduplicated_record_count",
    "omitted_record_count",
    "encoded_bytes",
    "projection_sha256",
    "reopen_projection_sha256",
    "prompt_bytes",
    "prompt_sha256",
    "reopen_prompt_sha256",
    "complete_context_count",
    "invalid_context_count",
    "rejected_context_count",
    "pending_count",
    "verified_count",
    "verifier_peer_record_count",
    "violations",
)
PRIVATE_COUNT_FIELDS = (
    "complete_context_count",
    "invalid_context_count",
    "rejected_context_count",
    "pending_count",
    "verified_count",
)
TOP_LEVEL_FIELDS = {
    "schema_version",
    "experiment",
    "effect_policy",
    "arms",
    "projection",
    "public_record_fields",
    "privacy",
    "fixture_generator",
    "fixture_defaults",
    "record_templates",
    "fixtures",
    "raw_rows",
    "metrics",
    "result",
    "native_confirmation",
    "registered_command",
}
FIXTURE_FIELDS = {
    "id",
    "target_overrides",
    "source_records",
    "private_rows",
    "expected_visible",
    "expected_useful",
    "expected_deduplicated",
    "expected_private_overrides",
}
TARGET_OVERRIDE_FIELDS = ("episode", "lane", "role")
RECORD_OVERRIDE_FIELDS = (
    "record_id",
    "run_id",
    "challenge_id",
    "source_episode",
    "source_lane",
    "source_attempt_id",
    "template",
    "facts",
    "payload_bytes",
)
KIND_FIELDS = {
    "analysis_claim": {"kind", "status", "summary", "evidence", "next_steps", "tool_count"},
    "host_observation": {
        "kind",
        "complete",
        "gap",
        "tool",
        "success",
        "source_bound",
        "facts",
    },
    "tactic_outcome": {"kind", "role", "tactic", "tool_profile", "status"},
    "failure": {"kind", "failure_kind", "subreason"},
}
PROPOSAL_FIELDS = {
    "table",
    "source_attempt_id",
    "run_id",
    "challenge_id",
    "episode",
    "lane",
    "role",
    "recipe_kind",
    "candidate",
}
VERIFICATION_FIELDS = {
    "table",
    "run_id",
    "challenge_id",
    "producer_attempt_id",
    "verifier_attempt_id",
    "recipe_kind",
    "candidate",
}
LOWER_SHA256 = re.compile(r"[0-9a-f]{64}")
CANDIDATE = re.compile(r"(?:INCYPHER|flag)\{[^{}\r\n]{1,512}\}", re.IGNORECASE)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _copy(value: Any) -> Any:
    return json.loads(_canonical(value))


def _exact_keys(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"M1 {label} schema changed")
    return value


def load_protocol(path: Path | str) -> dict[str, Any]:
    """Load only the exact registered M1 protocol."""
    protocol_path = Path(path)
    payload = protocol_path.read_bytes()
    if hashlib.sha256(payload).hexdigest() != EXPECTED_PROTOCOL_SHA256:
        raise ValueError("M1 protocol SHA-256 changed")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("M1 protocol is not valid JSON") from exc
    validate_protocol(value)
    _validate_command_addendum()
    return value


def _validate_command_addendum() -> None:
    payload = COMMAND_ADDENDUM_PATH.read_bytes()
    if hashlib.sha256(payload).hexdigest() != EXPECTED_COMMAND_ADDENDUM_SHA256:
        raise ValueError("M1 command addendum SHA-256 changed")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ValueError("M1 command addendum is not valid JSON") from exc
    document = _exact_keys(
        value,
        {
            "acceptance_changes",
            "protocol_sha256",
            "reason",
            "registered_command",
            "schema_version",
            "scope",
            "supersedes_registered_command",
        },
        "command addendum",
    )
    if (
        document["schema_version"] != 1
        or document["protocol_sha256"] != EXPECTED_PROTOCOL_SHA256
        or document["scope"] != "registered_command_only"
        or document["acceptance_changes"] is not False
        or document["supersedes_registered_command"] != FROZEN_PROTOCOL_COMMAND
        or document["registered_command"] != REGISTERED_COMMAND
        or not isinstance(document["reason"], str)
        or not document["reason"]
    ):
        raise ValueError("M1 command addendum changed")


def validate_protocol(protocol: object) -> None:
    """Fail closed on protocol, production-binding, fixture, or command drift."""
    document = _exact_keys(protocol, TOP_LEVEL_FIELDS, "protocol")
    if document["schema_version"] != 1 or document["experiment"] != "M1":
        raise ValueError("M1 protocol identity changed")
    if PROTOCOL_SHA256 != EXPECTED_PROTOCOL_SHA256:
        raise ValueError("production memory protocol binding changed")
    expected_effects = {field: False for field in EFFECT_FIELDS}
    if document["effect_policy"] != expected_effects:
        raise ValueError("M1 effect policy changed")

    arms = document["arms"]
    expected_arm_fields = {
        "id",
        "same_lane_analysis_claims",
        "same_lane_host_observations",
        "other_lane_host_observations",
        "other_lane_controller_records",
    }
    if not isinstance(arms, list) or len(arms) != 2:
        raise ValueError("M1 arms changed")
    for arm in arms:
        checked = _exact_keys(arm, expected_arm_fields, "arm")
        if any(type(checked[field]) is not bool for field in expected_arm_fields - {"id"}):
            raise TypeError("M1 arm flags are invalid")
    arm_ids = [arm["id"] for arm in arms]
    if arm_ids != ["lane_local_v1", "typed_challenge_v1"] or set(arm_ids) != MEMORY_ARMS:
        raise ValueError("M1 arm order or production arms changed")

    projection = document["projection"]
    if not isinstance(projection, dict):
        raise TypeError("M1 projection is invalid")
    required_projection = {
        "run_scope",
        "challenge_scope",
        "episode_rule",
        "verifier_prompt_record_count",
        "cross_lane_allowed_kinds",
        "same_lane_allowed_kinds",
        "controller_private_kinds",
        "kind_order",
        "ordering",
        "deduplication",
        "selection",
        "projection_bytes",
        "prompt_bytes",
        "byte_accounting",
        "cross_lane_analysis_prose_allowed",
        "candidate_context_in_prompt",
        "verification_in_prompt",
    }
    _exact_keys(projection, required_projection, "projection")
    if (
        projection["projection_bytes"] != PROJECTION_BYTES
        or projection["prompt_bytes"] != MAX_AGENT_MESSAGE_BYTES
        or projection["verifier_prompt_record_count"] != 0
        or projection["kind_order"]
        != ["host_observation", "tactic_outcome", "failure", "analysis_claim"]
        or projection["ordering"]
        != [
            "source_episode_desc",
            "source_lane_asc",
            "source_attempt_id_asc",
            "kind_order_asc",
            "record_id_asc",
        ]
        or projection["run_scope"] != "exact"
        or projection["challenge_scope"] != "exact"
        or projection["episode_rule"] != "source_episode < target_episode"
        or projection["cross_lane_analysis_prose_allowed"] is not False
        or projection["candidate_context_in_prompt"] is not False
        or projection["verification_in_prompt"] is not False
    ):
        raise ValueError("M1 projection contract changed")
    public_fields = document["public_record_fields"]
    if not isinstance(public_fields, dict) or set(public_fields) != set(PUBLIC_RECORD_FIELDS):
        raise ValueError("M1 public memory kinds changed")
    for kind, fields in PUBLIC_RECORD_FIELDS.items():
        if public_fields[kind] != list(fields):
            raise ValueError("M1 public record schema changed")

    defaults = document["fixture_defaults"]
    _exact_keys(
        defaults,
        {
            "target",
            "control_route",
            "prompt_construction",
            "role_route_overrides",
            "allowed_target_overrides",
            "record",
            "expected_private",
            "expansion",
            "allowed_record_overrides",
        },
        "fixture defaults",
    )
    if defaults["allowed_target_overrides"] != list(TARGET_OVERRIDE_FIELDS):
        raise ValueError("M1 target overrides changed")
    if defaults["allowed_record_overrides"] != list(RECORD_OVERRIDE_FIELDS):
        raise ValueError("M1 record overrides changed")
    if set(defaults["expected_private"]) != set(PRIVATE_COUNT_FIELDS) or any(
        type(defaults["expected_private"][field]) is not int
        or defaults["expected_private"][field] < 0
        for field in PRIVATE_COUNT_FIELDS
    ):
        raise ValueError("M1 private count defaults changed")
    RouteSpec.from_dict(defaults["control_route"])
    target = defaults["target"]
    _exact_keys(
        target,
        {"run_id", "challenge_id", "episode", "lane", "role", "challenge", "artifact_paths"},
        "target default",
    )
    _exact_keys(
        target["challenge"],
        {"id", "name", "category", "type", "description", "value"},
        "challenge default",
    )
    _exact_keys(
        defaults["record"],
        {"run_id", "challenge_id", "source_episode", "source_lane", "source_attempt_id"},
        "record default",
    )
    role_overrides = defaults["role_route_overrides"]
    if not isinstance(role_overrides, dict) or set(role_overrides) != {
        "specialist",
        "recovery",
        "verifier",
    }:
        raise ValueError("M1 route roles changed")
    for role, override in role_overrides.items():
        if not isinstance(override, dict) or set(override) != {"role", "verification_recipe"}:
            raise ValueError("M1 route override schema changed")
        merged = dict(defaults["control_route"])
        merged.update(override)
        if RouteSpec.from_dict(merged).role != role:
            raise ValueError("M1 route override role changed")

    templates = document["record_templates"]
    if not isinstance(templates, dict) or set(templates) != {
        "safe_host",
        "tactic",
        "failure",
        "incomplete_host",
        "private_host",
        "private_host_verified",
        "private_analysis",
    }:
        raise ValueError("M1 record templates changed")
    for name, template in templates.items():
        if not isinstance(template, dict) or template.get("kind") not in KIND_FIELDS:
            raise ValueError(f"M1 template {name} is invalid")
        if set(template) != KIND_FIELDS[template["kind"]]:
            raise ValueError(f"M1 template {name} schema changed")

    fixtures = document["fixtures"]
    if not isinstance(fixtures, list) or len(fixtures) != 14:
        raise ValueError("M1 fixture count changed")
    fixture_ids: set[str] = set()
    for fixture in fixtures:
        checked = _exact_keys(fixture, FIXTURE_FIELDS, "fixture")
        case_id = checked["id"]
        if not isinstance(case_id, str) or not case_id or case_id in fixture_ids:
            raise ValueError("M1 fixture id is invalid")
        fixture_ids.add(case_id)
        overrides = checked["target_overrides"]
        if not isinstance(overrides, dict) or not set(overrides) <= set(TARGET_OVERRIDE_FIELDS):
            raise ValueError(f"M1 fixture {case_id} has an invalid target override")
        records = checked["source_records"]
        if not isinstance(records, list):
            raise TypeError(f"M1 fixture {case_id} records are invalid")
        record_ids: set[str] = set()
        for record in records:
            if not isinstance(record, dict) or not set(record) <= set(RECORD_OVERRIDE_FIELDS):
                raise ValueError(f"M1 fixture {case_id} has an invalid record override")
            if not {"template", "record_id"} <= set(record):
                raise ValueError(f"M1 fixture {case_id} record identity is incomplete")
            if record["template"] not in templates or record["record_id"] in record_ids:
                raise ValueError(f"M1 fixture {case_id} record identity changed")
            record_ids.add(record["record_id"])
        private_rows = checked["private_rows"]
        if not isinstance(private_rows, list):
            raise TypeError(f"M1 fixture {case_id} private rows are invalid")
        for row in private_rows:
            if not isinstance(row, dict):
                raise TypeError(f"M1 fixture {case_id} private row is invalid")
            table = row.get("table")
            expected = (
                PROPOSAL_FIELDS
                if table == "candidate_proposals"
                else VERIFICATION_FIELDS
                if table == "candidate_verifications"
                else None
            )
            if expected is None or set(row) != expected:
                raise ValueError(f"M1 fixture {case_id} private row schema changed")
        for field in ("expected_visible", "expected_useful", "expected_deduplicated"):
            value = checked[field]
            if not isinstance(value, dict) or list(value) != arm_ids:
                raise ValueError(f"M1 fixture {case_id} {field} arms changed")
        for arm in arm_ids:
            visible = checked["expected_visible"][arm]
            useful = checked["expected_useful"][arm]
            deduplicated = checked["expected_deduplicated"][arm]
            if (
                not isinstance(visible, list)
                or any(record_id not in record_ids for record_id in visible)
                or not isinstance(useful, list)
                or any(record_id not in record_ids for record_id in useful)
                or not set(useful) <= set(visible)
                or type(deduplicated) is not int
                or deduplicated < 0
            ):
                raise ValueError(f"M1 fixture {case_id} expectations are invalid")
        private_overrides = checked["expected_private_overrides"]
        if not isinstance(private_overrides, dict) or not set(private_overrides) <= set(
            PRIVATE_COUNT_FIELDS
        ):
            raise ValueError(f"M1 fixture {case_id} private expectations changed")

    generator = document["fixture_generator"]
    if not isinstance(generator, dict) or generator.get("insertion_permutations") != list(
        PERMUTATIONS
    ):
        raise ValueError("M1 insertion permutations changed")
    if document["raw_rows"] != {
        "count": 112,
        "order": ["case_declared", "arm_declared", "permutation_declared"],
        "fields": list(RAW_FIELDS),
    }:
        raise ValueError("M1 raw row contract changed")
    result_contract = document["result"]
    if not isinstance(result_contract, dict):
        raise TypeError("M1 result contract is invalid")
    if (
        result_contract.get("required")
        != [
            "schema_version",
            "protocol_sha256",
            "source",
            "fixture_commitments",
            "raw_rows",
            "summaries",
            "gate",
            "selection",
            "provenance",
        ]
        or result_contract.get("source_schema")
        != ["clean", "commit", "files", "production_tree_sha256"]
        or result_contract.get("fixture_commitments_schema")
        != ["protocol_sha256", "expanded_fixture_sha256", "permutation_sha256"]
        or result_contract.get("provenance_schema")
        != ["command", "effect_counters", "environment", "started_at", "finished_at"]
        or result_contract.get("effect_counter_fields") != list(EFFECT_FIELDS)
        or result_contract.get("raw_rows_required") is not True
        or result_contract.get("validator_recomputes_from_raw_rows") is not True
        or result_contract.get("source_must_be_clean_merged_commit") is not True
    ):
        raise ValueError("M1 result contract changed")
    if document["registered_command"] != FROZEN_PROTOCOL_COMMAND:
        raise ValueError("M1 registered command changed")


def _expand_generated(value: object, inherited_payload_bytes: int | None = None) -> object:
    if isinstance(value, dict):
        if value.get("generator") == "large_fact":
            if not set(value) <= {"generator", "payload_bytes"}:
                raise ValueError("M1 large fact generator schema changed")
            payload_bytes = value.get("payload_bytes", inherited_payload_bytes)
            if type(payload_bytes) is not int or not 0 <= payload_bytes <= PROJECTION_BYTES:
                raise ValueError("M1 large fact payload is invalid")
            return "X" * payload_bytes
        if "generator" in value:
            raise ValueError("M1 fixture generator is unknown")
        return {
            key: _expand_generated(child, inherited_payload_bytes) for key, child in value.items()
        }
    if isinstance(value, list):
        return [_expand_generated(child, inherited_payload_bytes) for child in value]
    return value


def expand_fixture(fixture: Mapping[str, Any], protocol: Mapping[str, Any]) -> dict[str, Any]:
    """Expand one literal fixture without accepting unregistered override fields."""
    defaults = protocol["fixture_defaults"]
    target = _copy(defaults["target"])
    overrides = fixture["target_overrides"]
    if not isinstance(overrides, dict) or not set(overrides) <= set(TARGET_OVERRIDE_FIELDS):
        raise ValueError("M1 target overrides are invalid")
    target.update(_copy(overrides))
    if target["challenge_id"] != target["challenge"]["id"]:
        raise ValueError("M1 target and challenge identity differ")

    expanded_records: list[dict[str, Any]] = []
    for source in fixture["source_records"]:
        if not isinstance(source, dict) or not set(source) <= set(RECORD_OVERRIDE_FIELDS):
            raise ValueError("M1 source record overrides are invalid")
        template_name = source.get("template")
        if template_name not in protocol["record_templates"]:
            raise ValueError("M1 source record template is unknown")
        record = _copy(defaults["record"])
        record.update(_copy(protocol["record_templates"][template_name]))
        payload_bytes = source.get("payload_bytes")
        for key, value in source.items():
            if key not in {"template", "payload_bytes"}:
                record[key] = _copy(value)
        record = _expand_generated(record, payload_bytes)  # type: ignore[assignment]
        if not isinstance(record, dict):
            raise TypeError("M1 expanded record is invalid")
        expanded_records.append(record)

    expected_private = _copy(defaults["expected_private"])
    expected_private.update(_copy(fixture["expected_private_overrides"]))
    return {
        "id": fixture["id"],
        "target": target,
        "control_route": {
            **_copy(defaults["control_route"]),
            **_copy(defaults["role_route_overrides"][target["role"]]),
        },
        "source_records": expanded_records,
        "private_rows": _copy(fixture["private_rows"]),
        "expected_visible": _copy(fixture["expected_visible"]),
        "expected_useful": _copy(fixture["expected_useful"]),
        "expected_deduplicated": _copy(fixture["expected_deduplicated"]),
        "expected_private": expected_private,
    }


def _typed_record(value: Mapping[str, Any]) -> PublicMemoryRecord:
    common = {
        field: value[field]
        for field in (
            "record_id",
            "run_id",
            "challenge_id",
            "source_episode",
            "source_lane",
            "source_attempt_id",
        )
    }
    kind = value.get("kind")
    if kind == "analysis_claim":
        return AnalysisClaim(
            **common,
            status=value["status"],
            summary=value["summary"],
            evidence=tuple(value["evidence"]),
            next_steps=tuple(value["next_steps"]),
            tool_count=value["tool_count"],
        )
    if kind == "host_observation":
        return HostObservation(
            **common,
            complete=value["complete"],
            gap=value["gap"],
            tool=value["tool"],
            success=value["success"],
            source_bound=value["source_bound"],
            facts=value["facts"],
        )
    if kind == "tactic_outcome":
        return TacticOutcome(
            **common,
            role=value["role"],
            tactic=value["tactic"],
            tool_profile=value["tool_profile"],
            status=value["status"],
        )
    if kind == "failure":
        return FailureRecord(
            **common,
            failure_kind=value["failure_kind"],
            subreason=value["subreason"],
        )
    raise ValueError("M1 expanded record kind is unknown")


def _permute(values: Sequence[Any], name: str) -> list[Any]:
    copied = list(values)
    if name == "declared":
        return copied
    if name == "reverse":
        return list(reversed(copied))
    if name == "rotate_left_one":
        return copied[1:] + copied[:1] if copied else []
    if name == "even_then_odd":
        return copied[::2] + copied[1::2]
    raise ValueError("M1 insertion permutation is unknown")


def _contains_exact(value: object, expected: str) -> bool:
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return False
    if isinstance(value, str):
        return unicodedata.normalize("NFKC", value) == unicodedata.normalize("NFKC", expected)
    if isinstance(value, Mapping):
        return any(
            _contains_exact(key, expected) or _contains_exact(child, expected)
            for key, child in value.items()
        )
    if isinstance(value, Sequence):
        return any(_contains_exact(child, expected) for child in value)
    return False


def _private_aggregate(
    records: Sequence[PublicMemoryRecord], private_rows: Sequence[Mapping[str, Any]]
) -> CandidateMemoryAggregate:
    proposals = [row for row in private_rows if row["table"] == "candidate_proposals"]
    verification_rows = [row for row in private_rows if row["table"] == "candidate_verifications"]
    evidence_by_attempt: dict[str, CandidateEvidence] = {}
    proposal_by_attempt: dict[str, Mapping[str, Any]] = {}
    invalid = 0
    hosts = [record for record in records if isinstance(record, HostObservation)]

    for proposal in proposals:
        attempt_id = proposal["source_attempt_id"]
        if attempt_id in proposal_by_attempt:
            raise ValueError("M1 duplicate private proposal attempt")
        proposal_by_attempt[attempt_id] = proposal
        matching = [
            host
            for host in hosts
            if host.run_id == proposal["run_id"]
            and host.challenge_id == proposal["challenge_id"]
            and host.source_episode == proposal["episode"]
            and host.source_lane == proposal["lane"]
            and host.source_attempt_id == attempt_id
        ]
        host = matching[0] if len(matching) == 1 else None
        if len(matching) > 1:
            invalid += 1
        evidence_by_attempt[attempt_id] = CandidateEvidence(
            run_id=proposal["run_id"],
            challenge_id=proposal["challenge_id"],
            source_episode=proposal["episode"],
            source_lane=proposal["lane"],
            source_attempt_id=attempt_id,
            role=proposal["role"],
            recipe_kind=proposal["recipe_kind"],
            manifest_complete=bool(host is not None and host.complete),
            manifest_gap=(host.gap if host is not None else "missing_source_observation"),
            candidate_observed=bool(
                host is not None
                and host.success is True
                and host.source_bound
                and _contains_exact(host.facts, proposal["candidate"])
            ),
            candidate_supplied=False,
        )

    verification_by_producer: dict[str, CandidateVerification] = {}
    for row in verification_rows:
        producer = proposal_by_attempt.get(row["producer_attempt_id"])
        verifier = proposal_by_attempt.get(row["verifier_attempt_id"])
        verifier_evidence = evidence_by_attempt.get(row["verifier_attempt_id"])
        if (
            producer is None
            or verifier is None
            or verifier_evidence is None
            or verifier["role"] != "verifier"
            or producer["candidate"] != row["candidate"]
            or verifier["candidate"] != row["candidate"]
            or row["producer_attempt_id"] in verification_by_producer
        ):
            invalid += 1
            continue
        try:
            verification_by_producer[row["producer_attempt_id"]] = CandidateVerification(
                run_id=row["run_id"],
                challenge_id=row["challenge_id"],
                producer_attempt_id=row["producer_attempt_id"],
                verifier_attempt_id=row["verifier_attempt_id"],
                recipe_kind=row["recipe_kind"],
                candidate=row["candidate"],
                evidence=verifier_evidence,
            )
        except (TypeError, ValueError):
            invalid += 1

    contexts: list[CandidateContext] = []
    for proposal in proposals:
        if proposal["role"] == "verifier":
            continue
        evidence = evidence_by_attempt[proposal["source_attempt_id"]]
        try:
            contexts.append(
                CandidateContext(
                    run_id=proposal["run_id"],
                    challenge_id=proposal["challenge_id"],
                    source_episode=proposal["episode"],
                    source_lane=proposal["lane"],
                    source_attempt_id=proposal["source_attempt_id"],
                    role=proposal["role"],
                    recipe_kind=proposal["recipe_kind"],
                    candidate=proposal["candidate"],
                    evidence=evidence,
                    verification=verification_by_producer.get(proposal["source_attempt_id"]),
                )
            )
        except (TypeError, ValueError):
            invalid += 1
    return CandidateMemoryAggregate.from_contexts(contexts, invalid_context_count=invalid)


def _target(value: Mapping[str, Any]) -> MemoryTarget:
    return MemoryTarget(
        run_id=value["run_id"],
        challenge_id=value["challenge_id"],
        episode=value["episode"],
        lane=value["lane"],
        role=value["role"],
    )


def _challenge(value: Mapping[str, Any]) -> Challenge:
    challenge = value["challenge"]
    return Challenge(
        id=challenge["id"],
        name=challenge["name"],
        category=challenge["category"],
        type=challenge["type"],
        description=challenge["description"],
        value=challenge["value"],
        files=(),
        solved=False,
        max_attempts=None,
        attempts=0,
        timeout=None,
        shared=None,
    )


def _sensitive_values(protocol: Mapping[str, Any]) -> tuple[str, ...]:
    generator = protocol["fixture_generator"]
    return (
        generator["pending_candidate_canary"],
        generator["verified_candidate_canary"],
        generator["credential_canary"],
    )


def _sensitive_forms(protocol: Mapping[str, Any]) -> frozenset[str]:
    generator = protocol["fixture_generator"]
    raw_values = set(_sensitive_values(protocol))
    values = set(raw_values)
    for value in raw_values:
        raw = value.encode("utf-8")
        values.update(
            {
                hashlib.sha256(raw).hexdigest(),
                raw.hex(),
                raw.hex().upper(),
                base64.b64encode(raw).decode("ascii"),
                base64.b64encode(raw).decode("ascii").rstrip("="),
                base64.urlsafe_b64encode(raw).decode("ascii"),
                base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
                urllib.parse.quote_from_bytes(raw),
            }
        )
    values.update(
        {
            generator["pending_candidate_sha256"],
            generator["pending_candidate_hex"],
            generator["pending_candidate_base64"],
            generator["pending_candidate_base64url"],
            generator["pending_candidate_urlencoded"],
            generator["verified_candidate_sha256"],
            generator["absolute_path_canary"],
            generator["authority_canary"],
        }
    )
    return frozenset(unicodedata.normalize("NFKC", value) for value in values)


def _unsafe_scalar(value: str, sensitive_forms: frozenset[str]) -> bool:
    normalized = unicodedata.normalize("NFKC", value)
    if (
        normalized in sensitive_forms
        or CANDIDATE.search(normalized) is not None
        or LOWER_SHA256.fullmatch(normalized) is not None
        or normalized.startswith("/")
    ):
        return True
    try:
        return bool(urllib.parse.urlsplit(normalized).netloc)
    except ValueError:
        return True


def _privacy_violations(
    value: object,
    protocol: Mapping[str, Any],
    *,
    path: str = "record",
) -> list[str]:
    privacy = protocol["privacy"]
    sensitive_forms = _sensitive_forms(protocol)
    fragments = tuple(privacy["forbidden_field_fragments"])
    violations: list[str] = []

    def visit(child: object, location: str) -> None:
        if isinstance(child, bytes):
            try:
                child = child.decode("utf-8")
            except UnicodeDecodeError:
                violations.append(f"privacy_bytes:{location}")
                return
        if isinstance(child, str):
            if _unsafe_scalar(child, sensitive_forms):
                violations.append(f"privacy_value:{location}")
            return
        if isinstance(child, Mapping):
            for key, nested in child.items():
                if not isinstance(key, str):
                    violations.append(f"privacy_key_type:{location}")
                    continue
                normalized = unicodedata.normalize("NFKC", key).casefold()
                if any(fragment in normalized for fragment in fragments):
                    violations.append(f"privacy_key:{location}.{key}")
                visit(nested, f"{location}.{key}")
            return
        if isinstance(child, Sequence):
            for index, nested in enumerate(child):
                visit(nested, f"{location}[{index}]")

    visit(value, path)
    return violations


def _projection_inputs(
    expanded: Mapping[str, Any], permutation: str
) -> tuple[list[PublicMemoryRecord], CandidateMemoryAggregate]:
    records = [
        _typed_record(record) for record in _permute(expanded["source_records"], permutation)
    ]
    private_rows = _permute(expanded["private_rows"], permutation)
    aggregate = _private_aggregate(records, private_rows)
    return records, aggregate


def _project(
    expanded: Mapping[str, Any], arm: str, permutation: str
) -> tuple[MemoryProjection, CandidateMemoryAggregate, str]:
    records, aggregate = _projection_inputs(expanded, permutation)
    projection = project_memory(
        records,
        _target(expanded["target"]),
        arm=arm,
        candidate_memory=aggregate,
        projection_bytes=PROJECTION_BYTES,
    )
    prompt = build_turn_prompt(
        _challenge(expanded["target"]),
        list(expanded["target"]["artifact_paths"]),
        expanded["target"]["lane"],
        run_id=expanded["target"]["run_id"],
        episode=expanded["target"]["episode"],
        control_route=RouteSpec.from_dict(expanded["control_route"]),
        same_run_memory=projection,
    )
    return projection, aggregate, prompt


def _expected_unique_count(
    expanded: Mapping[str, Any], arm: str, protocol: Mapping[str, Any]
) -> tuple[int, int]:
    records = [_typed_record(record) for record in expanded["source_records"]]
    target = _target(expanded["target"])
    if target.role == "verifier":
        return 0, 0
    seen: set[str] = set()
    unique = 0
    deduplicated = 0
    for record in sorted(records, key=record_order):
        if (
            record.run_id != target.run_id
            or record.challenge_id != target.challenge_id
            or record.source_episode >= target.episode
            or (
                record.source_lane != target.lane
                and (arm != "typed_challenge_v1" or record.kind == "analysis_claim")
            )
        ):
            continue
        public = sanitize_public_value(
            record.public_record(), sensitive_values=_sensitive_values(protocol)
        )
        if not isinstance(public, dict):
            continue
        if record.kind == "analysis_claim" and "summary" not in public:
            public["summary"] = ""
        fingerprint = repeated_fingerprint(public)
        if fingerprint is not None and fingerprint in seen:
            deduplicated += 1
            continue
        if fingerprint is not None:
            seen.add(fingerprint)
        unique += 1
    return unique, deduplicated


def _row(
    expanded: Mapping[str, Any],
    arm: str,
    permutation: str,
    protocol: Mapping[str, Any],
) -> dict[str, object]:
    projection, aggregate, prompt = _project(expanded, arm, permutation)
    reopened, reopened_aggregate, reopened_prompt = _project(expanded, arm, permutation)
    records = projection.as_public()
    counts = aggregate.public_counts()
    reopened_counts = reopened_aggregate.public_counts()
    prompt_document = json.loads(prompt)
    violations: list[str] = []
    expected_visible = expanded["expected_visible"][arm]
    expected_useful = expanded["expected_useful"][arm]
    visible = list(projection.record_ids)
    if visible != expected_visible:
        violations.append("visibility_or_order")
    if counts != expanded["expected_private"]:
        violations.append("private_counts")
    if reopened_counts != counts:
        violations.append("reopen_private_counts")
    if projection.deduplicated_record_count != expanded["expected_deduplicated"][arm]:
        violations.append("deduplication")
    unique_count, independent_deduplicated = _expected_unique_count(expanded, arm, protocol)
    if independent_deduplicated != projection.deduplicated_record_count:
        violations.append("deduplication_recompute")
    if projection.omitted_record_count != unique_count - len(visible):
        violations.append("omission_recompute")
    if projection.encoded_bytes != len(canonical_bytes(records)):
        violations.append("projection_byte_recompute")
    if projection.encoded_bytes > protocol["projection"]["projection_bytes"]:
        violations.append("projection_budget")
    expected_fields = protocol["public_record_fields"]
    for record in records:
        kind = record.get("kind")
        if kind not in expected_fields or set(record) != set(expected_fields[kind]):
            violations.append("public_record_schema")
            break
    violations.extend(_privacy_violations(records, protocol))
    input_records, _ = _projection_inputs(expanded, permutation)
    visible_by_id = {record.record_id: record for record in input_records}
    order_keys = [record_order(visible_by_id[record_id]) for record_id in visible]
    if order_keys != sorted(order_keys):
        violations.append("canonical_order")
    if prompt_document.get("same_run_memory") != records:
        violations.append("prompt_projection")
    if prompt_document.get("control_route") != expanded["control_route"]:
        violations.append("prompt_route")
    prompt_bytes = prompt.encode("utf-8")
    if len(prompt_bytes) > protocol["projection"]["prompt_bytes"]:
        violations.append("prompt_budget")
    if _privacy_violations(prompt_document, protocol, path="prompt"):
        violations.append("prompt_privacy")
    verifier_peer_count = len(records) if expanded["target"]["role"] == "verifier" else 0
    if verifier_peer_count != protocol["projection"]["verifier_prompt_record_count"]:
        violations.append("verifier_peer_memory")

    fingerprints: set[str] = set()
    repeated = 0
    for record in records:
        fingerprint = repeated_fingerprint(record)
        if fingerprint is not None and fingerprint in fingerprints:
            repeated += 1
        if fingerprint is not None:
            fingerprints.add(fingerprint)
    useful_count = sum(record_id in set(expected_useful) for record_id in visible)
    kind_counts = {
        kind: sum(record.get("kind") == kind for record in records)
        for kind in protocol["projection"]["kind_order"]
    }
    return {
        "case_id": expanded["id"],
        "arm_id": arm,
        "permutation": permutation,
        "visible_record_ids": visible,
        "visible_kind_counts": kind_counts,
        "useful_record_count": useful_count,
        "repeated_fingerprint_count": repeated,
        "deduplicated_record_count": projection.deduplicated_record_count,
        "omitted_record_count": projection.omitted_record_count,
        "encoded_bytes": projection.encoded_bytes,
        "projection_sha256": hashlib.sha256(projection.canonical_bytes()).hexdigest(),
        "reopen_projection_sha256": hashlib.sha256(reopened.canonical_bytes()).hexdigest(),
        "prompt_bytes": len(prompt_bytes),
        "prompt_sha256": hashlib.sha256(prompt_bytes).hexdigest(),
        "reopen_prompt_sha256": hashlib.sha256(reopened_prompt.encode("utf-8")).hexdigest(),
        **counts,
        "verifier_peer_record_count": verifier_peer_count,
        "violations": sorted(set(violations)),
    }


def _expected_identity(protocol: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    return [
        (fixture["id"], arm["id"], permutation)
        for fixture in protocol["fixtures"]
        for arm in protocol["arms"]
        for permutation in protocol["fixture_generator"]["insertion_permutations"]
    ]


def recompute_views(
    raw_rows: object, protocol: Mapping[str, Any]
) -> tuple[dict[str, object], dict[str, object], dict[str, str]]:
    """Recompute summaries, safety gate, and frozen selection from raw rows."""
    arms = [arm["id"] for arm in protocol["arms"]]
    rows = raw_rows if isinstance(raw_rows, list) else []
    expected_identity = _expected_identity(protocol)
    identities = [
        (row.get("case_id"), row.get("arm_id"), row.get("permutation"))
        if isinstance(row, dict)
        else (None, None, None)
        for row in rows
    ]
    exact_schema = all(isinstance(row, dict) and set(row) == set(RAW_FIELDS) for row in rows)
    exact_order = identities == expected_identity
    row_validity: dict[int, bool] = {}
    fixtures = {fixture["id"]: fixture for fixture in protocol["fixtures"]}
    expanded_fixtures = {
        fixture["id"]: expand_fixture(fixture, protocol) for fixture in protocol["fixtures"]
    }
    for index, row in enumerate(rows):
        valid = isinstance(row, dict) and set(row) == set(RAW_FIELDS)
        if not valid:
            row_validity[index] = False
            continue
        if (
            not isinstance(row["case_id"], str)
            or not isinstance(row["arm_id"], str)
            or not isinstance(row["permutation"], str)
        ):
            row_validity[index] = False
            continue
        fixture = fixtures.get(row["case_id"])
        arm = row["arm_id"]
        if fixture is None or arm not in arms or row["permutation"] not in PERMUTATIONS:
            row_validity[index] = False
            continue
        expected_private = dict(protocol["fixture_defaults"]["expected_private"])
        expected_private.update(fixture["expected_private_overrides"])
        expected_visible = fixture["expected_visible"][arm]
        expected_useful = fixture["expected_useful"][arm]
        visible = row["visible_record_ids"]
        if not isinstance(visible, list):
            row_validity[index] = False
            continue
        digest_fields = (
            "projection_sha256",
            "reopen_projection_sha256",
            "prompt_sha256",
            "reopen_prompt_sha256",
        )
        digests_valid = all(
            isinstance(row[field], str) and LOWER_SHA256.fullmatch(row[field]) is not None
            for field in digest_fields
        )
        integers = (
            "useful_record_count",
            "repeated_fingerprint_count",
            "deduplicated_record_count",
            "omitted_record_count",
            "encoded_bytes",
            "prompt_bytes",
            *PRIVATE_COUNT_FIELDS,
            "verifier_peer_record_count",
        )
        integer_valid = all(type(row[field]) is int and row[field] >= 0 for field in integers)
        useful = sum(record_id in set(expected_useful) for record_id in visible)
        expected_row = _row(
            expanded_fixtures[row["case_id"]],
            arm,
            row["permutation"],
            protocol,
        )
        valid = bool(
            digests_valid
            and integer_valid
            and visible == expected_visible
            and row["useful_record_count"] == useful
            and row["repeated_fingerprint_count"] == 0
            and row["deduplicated_record_count"] == fixture["expected_deduplicated"][arm]
            and all(row[field] == expected_private[field] for field in PRIVATE_COUNT_FIELDS)
            and row["invalid_context_count"] == 0
            and row["encoded_bytes"] <= protocol["projection"]["projection_bytes"]
            and row["prompt_bytes"] <= protocol["projection"]["prompt_bytes"]
            and row["verifier_peer_record_count"] == 0
            and row["violations"] == []
            and row["projection_sha256"] == row["reopen_projection_sha256"]
            and row["prompt_sha256"] == row["reopen_prompt_sha256"]
            and row == expected_row
        )
        row_validity[index] = valid

    permutation_stable = True
    for fixture in protocol["fixtures"]:
        for arm in arms:
            group = [
                row
                for row in rows
                if isinstance(row, dict)
                and row.get("case_id") == fixture["id"]
                and row.get("arm_id") == arm
            ]
            if len(group) != len(PERMUTATIONS):
                permutation_stable = False
                continue
            if (
                len({row.get("projection_sha256") for row in group}) != 1
                or len({row.get("prompt_sha256") for row in group}) != 1
            ):
                permutation_stable = False

    summaries: dict[str, object] = {}
    for arm in arms:
        indexed = [
            (index, row)
            for index, row in enumerate(rows)
            if isinstance(row, dict) and row.get("arm_id") == arm
        ]
        arm_rows = [row for _, row in indexed]
        eligible = bool(
            exact_schema
            and exact_order
            and permutation_stable
            and len(arm_rows) == len(protocol["fixtures"]) * len(PERMUTATIONS)
            and all(row_validity.get(index, False) for index, _ in indexed)
        )
        summaries[arm] = {
            "row_count": len(arm_rows),
            "useful_record_count": sum(
                row["useful_record_count"]
                for row in arm_rows
                if type(row.get("useful_record_count")) is int
            ),
            "repeated_fingerprint_count": sum(
                row["repeated_fingerprint_count"]
                for row in arm_rows
                if type(row.get("repeated_fingerprint_count")) is int
            ),
            "deduplicated_record_count": sum(
                row["deduplicated_record_count"]
                for row in arm_rows
                if type(row.get("deduplicated_record_count")) is int
            ),
            "omitted_record_count": sum(
                row["omitted_record_count"]
                for row in arm_rows
                if type(row.get("omitted_record_count")) is int
            ),
            "encoded_bytes": sum(
                row["encoded_bytes"] for row in arm_rows if type(row.get("encoded_bytes")) is int
            ),
            "prompt_bytes": sum(
                row["prompt_bytes"] for row in arm_rows if type(row.get("prompt_bytes")) is int
            ),
            "eligible": eligible,
        }
    all_rows_valid = bool(
        len(rows) == protocol["raw_rows"]["count"]
        and exact_schema
        and exact_order
        and len(row_validity) == len(rows)
        and all(row_validity.values())
    )
    gate = {
        "passed": all_rows_valid and permutation_stable,
        "expected_raw_row_count": protocol["raw_rows"]["count"],
        "actual_raw_row_count": len(rows),
        "exact_schema": exact_schema,
        "exact_order": exact_order,
        "all_rows_valid": all_rows_valid,
        "permutation_stable": permutation_stable,
        "eligible_arms": [arm for arm in arms if summaries[arm]["eligible"]],
    }
    baseline = summaries["lane_local_v1"]
    typed = summaries["typed_challenge_v1"]
    selected = "lane_local_v1"
    if (
        baseline["eligible"]
        and typed["eligible"]
        and typed["useful_record_count"] > baseline["useful_record_count"]
        and typed["repeated_fingerprint_count"] <= baseline["repeated_fingerprint_count"]
    ):
        selected = "typed_challenge_v1"
    return summaries, gate, {"arm": selected}


def _source_files(protocol_path: Path) -> tuple[Path, ...]:
    paths = [Path(__file__).resolve(), protocol_path.resolve(), COMMAND_ADDENDUM_PATH.resolve()]
    paths.extend(sorted((ROOT / "rapido").rglob("*.py")))
    return tuple(dict.fromkeys(paths))


def git_source_identity(protocol_path: Path) -> dict[str, object]:
    status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    files = {
        str(path.relative_to(ROOT)): _file_digest(path) for path in _source_files(protocol_path)
    }
    production = {path: digest for path, digest in files.items() if path.startswith("rapido/")}
    tree_payload = "".join(f"{path}\0{digest}\n" for path, digest in sorted(production.items()))
    return {
        "clean": not status,
        "commit": commit,
        "files": files,
        "production_tree_sha256": hashlib.sha256(tree_payload.encode("utf-8")).hexdigest(),
    }


def _verify_merged_source(source: Mapping[str, Any]) -> None:
    commit = source["commit"]
    commit_check = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=ROOT,
        capture_output=True,
        check=False,
    )
    if commit_check.returncode != 0:
        raise ValueError("M1 source commit is unavailable")
    remote_head = subprocess.run(
        ["git", "symbolic-ref", "refs/remotes/origin/HEAD"],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    if remote_head.returncode != 0:
        raise ValueError("M1 remote default branch is unavailable")
    remote_ref = remote_head.stdout.strip()
    if not remote_ref.startswith("refs/remotes/origin/"):
        raise ValueError("M1 remote default branch is invalid")
    remote_tip = subprocess.run(
        ["git", "rev-parse", remote_ref],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    if remote_tip.returncode != 0 or remote_tip.stdout.strip() != commit:
        raise ValueError("M1 source is not the merged remote default-branch tip")
    for path, digest in source["files"].items():
        committed = subprocess.run(
            ["git", "show", f"{commit}:{path}"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        if committed.returncode != 0 or hashlib.sha256(committed.stdout).hexdigest() != digest:
            raise ValueError("M1 source file does not match its merged commit")


def _environment() -> dict[str, object]:
    return {
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
    }


class OfflineEffectFence(AbstractContextManager["OfflineEffectFence"]):
    """Block network/process entry points while pure rows are evaluated."""

    def __init__(self) -> None:
        self.counts = {field: 0 for field in EFFECT_FIELDS}
        self._restorations: list[tuple[object, str, object]] = []

    def _block(self, owner: object, name: str, effect: str) -> None:
        original = getattr(owner, name)

        def blocked(*args: object, **kwargs: object) -> object:
            del args, kwargs
            self.counts[effect] += 1
            raise RuntimeError(f"M1 blocked forbidden {effect} access")

        self._restorations.append((owner, name, original))
        setattr(owner, name, blocked)

    def __enter__(self) -> Self:
        self._block(_socket, "socket", "network")
        self._block(socket, "socket", "network")
        self._block(subprocess, "Popen", "containers")
        for name in ("fork", "forkpty", "posix_spawn", "posix_spawnp", "system"):
            if hasattr(os, name):
                self._block(os, name, "containers")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        while self._restorations:
            owner, name, original = self._restorations.pop()
            setattr(owner, name, original)


def _fixture_commitments(
    protocol: Mapping[str, Any], expanded: Sequence[Mapping[str, Any]]
) -> dict[str, str]:
    public_expanded = sanitize_public_value(
        expanded,
        sensitive_values=_sensitive_values(protocol),
    )
    if public_expanded is None or _privacy_violations(public_expanded, protocol):
        raise ValueError("M1 expanded fixture commitment is not privacy safe")
    return {
        "protocol_sha256": EXPECTED_PROTOCOL_SHA256,
        "expanded_fixture_sha256": _digest(public_expanded),
        "permutation_sha256": _digest(protocol["fixture_generator"]["insertion_permutations"]),
    }


def _result_has_private_material(result: Mapping[str, Any], protocol: Mapping[str, Any]) -> bool:
    encoded = _canonical(result).decode("ascii")
    return any(form in encoded for form in _sensitive_forms(protocol))


def validate_result(
    result: object,
    protocol: Mapping[str, Any],
    *,
    protocol_path: Path = DEFAULT_PROTOCOL_PATH,
    require_clean_source: bool = True,
    expected_source: Mapping[str, object] | None = None,
) -> None:
    """Validate stored views, source commitments, privacy, and raw-derived selection."""
    expected_top = set(protocol["result"]["required"])
    document = _exact_keys(result, expected_top, "result")
    if document["schema_version"] != 1 or document["protocol_sha256"] != EXPECTED_PROTOCOL_SHA256:
        raise ValueError("M1 result identity changed")
    commitments = document["fixture_commitments"]
    if not isinstance(commitments, dict) or set(commitments) != {
        "protocol_sha256",
        "expanded_fixture_sha256",
        "permutation_sha256",
    }:
        raise ValueError("M1 fixture commitments changed")
    expanded = [expand_fixture(fixture, protocol) for fixture in protocol["fixtures"]]
    if commitments != _fixture_commitments(protocol, expanded):
        raise ValueError("M1 fixture commitments do not replay")

    with OfflineEffectFence() as validation_fence:
        summaries, gate, selection = recompute_views(document["raw_rows"], protocol)
    if validation_fence.counts != {field: 0 for field in EFFECT_FIELDS}:
        raise ValueError("M1 validation attempted a forbidden effect")
    if document["summaries"] != summaries:
        raise ValueError("M1 summaries differ from raw recomputation")
    if document["gate"] != gate:
        raise ValueError("M1 gate differs from raw recomputation")
    if document["selection"] != selection:
        raise ValueError("M1 selection differs from raw recomputation")

    source = _exact_keys(
        document["source"],
        {"clean", "commit", "files", "production_tree_sha256"},
        "source",
    )
    if require_clean_source and source["clean"] is not True:
        raise ValueError("M1 source was not clean")
    if (
        not isinstance(source["commit"], str)
        or len(source["commit"]) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in source["commit"])
        or not isinstance(source["files"], dict)
    ):
        raise ValueError("M1 source identity is invalid")
    required_paths = {
        str(path.relative_to(ROOT)) for path in _source_files(protocol_path.resolve())
    }
    if set(source["files"]) != required_paths:
        raise ValueError("M1 source file manifest changed")
    digests = [source["production_tree_sha256"], *source["files"].values()]
    if any(
        not isinstance(digest, str) or LOWER_SHA256.fullmatch(digest) is None for digest in digests
    ):
        raise ValueError("M1 source digest is invalid")
    production = {
        path: digest for path, digest in source["files"].items() if path.startswith("rapido/")
    }
    tree_payload = "".join(f"{path}\0{digest}\n" for path, digest in sorted(production.items()))
    if hashlib.sha256(tree_payload.encode("utf-8")).hexdigest() != source["production_tree_sha256"]:
        raise ValueError("M1 production tree commitment changed")
    if expected_source is not None and source != expected_source:
        raise ValueError("M1 source changed during evaluation")
    current_files = {
        str(path.relative_to(ROOT)): _file_digest(path)
        for path in _source_files(protocol_path.resolve())
    }
    if source["files"] != current_files:
        raise ValueError("M1 source files differ from the recorded evaluation")
    if require_clean_source:
        _verify_merged_source(source)

    provenance = _exact_keys(
        document["provenance"],
        {"command", "effect_counters", "environment", "started_at", "finished_at"},
        "provenance",
    )
    if provenance["command"] != REGISTERED_COMMAND:
        raise ValueError("M1 result command changed")
    if provenance["effect_counters"] != {field: 0 for field in EFFECT_FIELDS}:
        raise ValueError("M1 forbidden effect occurred")
    if not isinstance(provenance["environment"], dict) or not provenance["environment"]:
        raise ValueError("M1 result environment is invalid")
    timestamps = []
    for field in ("started_at", "finished_at"):
        try:
            parsed = datetime.fromisoformat(provenance[field])
        except (TypeError, ValueError) as exc:
            raise ValueError("M1 result timestamp is invalid") from exc
        if parsed.tzinfo is None:
            raise ValueError("M1 result timestamp lacks timezone")
        timestamps.append(parsed)
    if timestamps[1] < timestamps[0]:
        raise ValueError("M1 result timestamps are reversed")
    if _result_has_private_material(document, protocol):
        raise ValueError("M1 result contains private fixture material")


def run_comparison(
    protocol_path: Path | str = DEFAULT_PROTOCOL_PATH,
    *,
    require_clean_source: bool = True,
    timestamp: str | None = None,
) -> dict[str, object]:
    """Produce the 112-row result in memory; never write an artifact."""
    path = Path(protocol_path).resolve()
    protocol = load_protocol(path)
    source = git_source_identity(path)
    if require_clean_source and source["clean"] is not True:
        raise RuntimeError("M1 measurement requires clean merged source")
    started_at = timestamp or datetime.now(UTC).isoformat()
    expanded = [expand_fixture(fixture, protocol) for fixture in protocol["fixtures"]]
    rows: list[dict[str, object]] = []
    with OfflineEffectFence() as fence:
        for fixture in expanded:
            for arm in protocol["arms"]:
                for permutation in protocol["fixture_generator"]["insertion_permutations"]:
                    rows.append(_row(fixture, arm["id"], permutation, protocol))
        summaries, gate, selection = recompute_views(rows, protocol)
    if fence.counts != {field: 0 for field in EFFECT_FIELDS}:
        raise RuntimeError("M1 attempted a forbidden effect")
    finished_at = timestamp or datetime.now(UTC).isoformat()
    result: dict[str, object] = {
        "schema_version": 1,
        "protocol_sha256": EXPECTED_PROTOCOL_SHA256,
        "source": source,
        "fixture_commitments": _fixture_commitments(protocol, expanded),
        "raw_rows": rows,
        "summaries": summaries,
        "gate": gate,
        "selection": selection,
        "provenance": {
            "command": REGISTERED_COMMAND,
            "effect_counters": dict(fence.counts),
            "environment": _environment(),
            "started_at": started_at,
            "finished_at": finished_at,
        },
    }
    validate_result(
        result,
        protocol,
        protocol_path=path,
        require_clean_source=require_clean_source,
        expected_source=source,
    )
    return result


def canonical_result_bytes(result: Mapping[str, Any]) -> bytes:
    """Return the one registered deterministic result representation."""
    return _canonical(result) + b"\n"


def _write_new(path: Path, payload: bytes) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError("M1 output already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    if temporary.exists() or temporary.is_symlink():
        raise FileExistsError("M1 temporary output already exists")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        if temporary.read_bytes() != payload:
            raise OSError("M1 temporary output verification failed")
        os.link(temporary, path)
        _fsync_directory(path.parent)
    finally:
        if temporary.exists():
            temporary.unlink()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.protocol.resolve() != DEFAULT_PROTOCOL_PATH:
        parser.error("--protocol must be the frozen M1 protocol path")
    if arguments.output.resolve() != DEFAULT_RESULT_PATH:
        parser.error("--output must be the frozen M1 result path")
    if Path(sys.executable).absolute() != (ROOT / ".venv/bin/python").absolute():
        parser.error("M1 must run with the preregistered .venv/bin/python interpreter")
    if arguments.output.exists() or arguments.output.is_symlink():
        raise FileExistsError("M1 output already exists")
    result = run_comparison(arguments.protocol, require_clean_source=True)
    payload = canonical_result_bytes(result)
    stored = json.loads(payload)
    validate_result(
        stored,
        load_protocol(arguments.protocol),
        protocol_path=arguments.protocol.resolve(),
        require_clean_source=True,
        expected_source=result["source"],
    )
    if canonical_result_bytes(stored) != payload:
        raise ValueError("M1 result is not canonical")
    _write_new(arguments.output, payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
