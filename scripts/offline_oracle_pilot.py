#!/usr/bin/env python3
"""Run a paired native-model pilot against private synthetic answer keys."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import hmac
import io
import json
import math
import os
import re
import stat
import subprocess
import tempfile
import time
import urllib.parse
import zipfile
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Literal

from rapido.board import Challenge
from rapido.codex_app import (
    CodexAppClient,
    CodexAppError,
    ModelValidationError,
    TurnTimeoutError,
)
from rapido.config import validate_codex_home
from rapido.evidence import EvidenceBatch, RunEvidence
from rapido.memory import MemoryTarget, project_memory
from rapido.orchestrator import _normalize_tool_calls
from rapido.routing import baseline_route
from rapido.solver import (
    OFFLINE_DEVELOPER_INSTRUCTIONS,
    SOLVER_OUTPUT_SCHEMA,
    SolverFinding,
    SolverOutputError,
    build_turn_prompt,
    candidate_is_eligible,
    challenge_candidate_prose,
)
from rapido.state import StateStore
from rapido.tools import ToolRegistry

TURN_TIMEOUT_SECONDS = 300.0
MAX_WORKSPACE_BYTES = 192 * 1024 * 1024
ORACLE_SCHEMA = "rapido-offline-oracle-v1"
RECEIPT_SCHEMA = "rapido-offline-oracle-pilot-v1"
VERIFIER_REPAIR_RECEIPT_SCHEMA = "rapido-offline-verifier-repair-v1"
MODEL_COMPARISON_EXPERIMENT = "model-comparison"
VERIFIER_REPAIR_EXPERIMENT = "verifier-repair"
_SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_IMAGE_ID_RE = re.compile(r"sha256:[0-9a-f]{64}")
_CLOSED_LABEL_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_ORACLE_ID_RE = re.compile(r"[a-z][a-z0-9_.-]{0,99}")

Outcome = Literal["correct", "wrong", "unverifiable", "timeout", "provider_failure"]
VerifierOutcome = Literal[
    "verified_correct",
    "verified_wrong",
    "rejected_correct",
    "rejected_wrong",
    "no_candidate",
    "solver_output",
    "timeout",
    "provider_failure",
]
VerifierRejection = Literal[
    "candidate_evidence_incomplete",
    "candidate_ineligible",
    "candidate_supplied",
    "candidate_unobserved",
    "verifier_requires_fixed_observation",
    "solver_output",
]
_REPAIRABLE_VERIFIER_REJECTIONS = frozenset(
    {"candidate_unobserved", "verifier_requires_fixed_observation"}
)
_VERIFIER_MODEL = "gpt-daybreak-blue-latest"
_VERIFIER_EFFORT = "xhigh"


@dataclass(frozen=True)
class Arm:
    id: str
    model: str
    effort: str


ARMS = (
    Arm("daybreak_xhigh", "gpt-daybreak-blue-latest", "xhigh"),
    Arm("luna_xhigh", "gpt-5.6-luna", "xhigh"),
)


@dataclass(frozen=True)
class VerifierArm:
    id: str
    continuation: bool


VERIFIER_ARMS = (
    VerifierArm("one_shot", False),
    VerifierArm("evidence_repair", True),
)


@dataclass(frozen=True)
class FixtureSpec:
    id: str
    number: int
    family: str
    artifact_name: str
    description: str
    encoder: Callable[[str, int], bytes]

    def material(self, answer: str) -> bytes:
        return self.encoder(answer, self.number)


@dataclass(frozen=True)
class PilotConfig:
    codex_binary: str
    codex_home: Path
    work_root: Path
    oracle_key_file: Path
    source_sha: str | None = None
    image_id: str | None = None
    oracle_id: str = ORACLE_SCHEMA
    max_workspace_bytes: int = MAX_WORKSPACE_BYTES


@dataclass(frozen=True)
class Measurement:
    task_id: str
    family: str
    arm: Arm
    outcome: Outcome
    fixture_elapsed_seconds: float
    turn_elapsed_seconds: float
    failure_class: str | None
    source_proved: bool
    tool_calls: int
    tool_errors: Mapping[str, object]
    native_usage: Mapping[str, object]

    def public(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "family": self.family,
            "arm": self.arm.id,
            "model": self.arm.model,
            "effort": self.arm.effort,
            "role": "specialist",
            "outcome": self.outcome,
            "elapsed_seconds": round(self.fixture_elapsed_seconds + self.turn_elapsed_seconds, 3),
            "spans": {
                "fixture_setup_seconds": round(self.fixture_elapsed_seconds, 3),
                "turn_seconds": round(self.turn_elapsed_seconds, 3),
            },
            "failure_class": self.failure_class,
            "source_proved": self.source_proved,
            "tool_calls": self.tool_calls,
            "tool_errors": dict(self.tool_errors),
            "native_usage": dict(self.native_usage),
        }


@dataclass(frozen=True)
class VerifierTurnEvaluation:
    outcome: VerifierOutcome
    rejection_reason: VerifierRejection | None
    candidate: str | None = field(default=None, repr=False)

    def public(self) -> dict[str, object]:
        return {
            "outcome": self.outcome,
            "rejection_reason": self.rejection_reason,
            "verified": self.rejection_reason is None
            and self.outcome in {"verified_correct", "verified_wrong"},
        }


@dataclass(frozen=True)
class VerifierMeasurement:
    task_id: str
    family: str
    arm: VerifierArm
    first: VerifierTurnEvaluation
    final: VerifierTurnEvaluation
    fixture_elapsed_seconds: float
    first_turn_seconds: float
    repair_turn_seconds: float
    repair_attempted: bool
    continuation_count: int
    same_thread: bool
    continuation_prompt_candidate_free: bool
    first_tool_calls: int
    final_tool_calls: int
    cumulative_tool_calls: int
    tool_errors: Mapping[str, object]
    first_native_usage: Mapping[str, object]
    final_native_usage: Mapping[str, object]
    failure_class: str | None

    def public(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "family": self.family,
            "arm": self.arm.id,
            "model": _VERIFIER_MODEL,
            "effort": _VERIFIER_EFFORT,
            "role": "verifier",
            "first": self.first.public(),
            "final": self.final.public(),
            "repair_attempted": self.repair_attempted,
            "continuation_count": self.continuation_count,
            "same_thread": self.same_thread,
            "continuation_prompt_candidate_free": self.continuation_prompt_candidate_free,
            "elapsed_seconds": round(
                self.fixture_elapsed_seconds + self.first_turn_seconds + self.repair_turn_seconds,
                3,
            ),
            "spans": {
                "fixture_setup_seconds": round(self.fixture_elapsed_seconds, 3),
                "first_turn_seconds": round(self.first_turn_seconds, 3),
                "repair_turn_seconds": round(self.repair_turn_seconds, 3),
            },
            "tool_calls": {
                "first_turn": self.first_tool_calls,
                "final_turn": self.final_tool_calls,
                "cumulative": self.cumulative_tool_calls,
            },
            "tool_errors": dict(self.tool_errors),
            "native_usage": {
                "first_turn": dict(self.first_native_usage),
                "final_turn": dict(self.final_native_usage),
            },
            "failure_class": self.failure_class,
        }


def _plain_text(answer: str, variant: int) -> bytes:
    return (
        f"Synthetic offline record\nrecord={variant:02d}\nstatus=complete\nfinal={answer}\n"
    ).encode("ascii")


def _structured_json(answer: str, variant: int) -> bytes:
    return json.dumps(
        {"record": variant, "status": "complete", "result": {"answer": answer}},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _base64_text(answer: str, variant: int) -> bytes:
    encoded = base64.b64encode(answer.encode("ascii")).decode("ascii")
    return f"record={variant:02d}\nencoding=base64\npayload={encoded}\n".encode("ascii")


def _hex_text(answer: str, variant: int) -> bytes:
    return f"record={variant:02d}\nencoding=hex\npayload={answer.encode().hex()}\n".encode("ascii")


def _zip_archive(answer: str, variant: int) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in (
            ("notes/readme.txt", "Synthetic offline archive.\n"),
            ("evidence/result.txt", f"record={variant:02d}\nfinal={answer}\n"),
        ):
            member = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            member.compress_type = zipfile.ZIP_DEFLATED
            member.external_attr = 0o600 << 16
            archive.writestr(member, payload)
    return output.getvalue()


def _binary_record(answer: str, variant: int) -> bytes:
    return (
        b"\x00RAPIDO_SYNTHETIC\x00"
        + f"record={variant:02d}".encode("ascii")
        + b"\x00final="
        + answer.encode("ascii")
        + b"\x00END\xff"
    )


def fixture_catalogue() -> tuple[FixtureSpec, ...]:
    families: tuple[tuple[str, str, str, Callable[[str, int], bytes]], ...] = (
        (
            "plain_text",
            "artifact.txt",
            "Inspect the text record and return its exact final value.",
            _plain_text,
        ),
        (
            "structured_json",
            "artifact.json",
            "Inspect the JSON record and return the exact nested answer value.",
            _structured_json,
        ),
        (
            "base64",
            "artifact.b64.txt",
            "Inspect the record, decode its declared base64 payload, and return the result.",
            _base64_text,
        ),
        (
            "hex",
            "artifact.hex.txt",
            "Inspect the record, decode its declared hexadecimal payload, and return the result.",
            _hex_text,
        ),
        (
            "zip",
            "artifact.zip",
            "Inspect the safe ZIP and return the final value in evidence/result.txt.",
            _zip_archive,
        ),
        (
            "binary_strings",
            "artifact.bin",
            "Inspect the synthetic binary strings and return the value marked final.",
            _binary_record,
        ),
    )
    fixtures: list[FixtureSpec] = []
    number = 0
    for family, artifact_name, description, encoder in families:
        for _ in range(2):
            number += 1
            fixtures.append(
                FixtureSpec(
                    id=f"task-{number:02d}",
                    number=number,
                    family=family,
                    artifact_name=artifact_name,
                    description=description,
                    encoder=encoder,
                )
            )
    return tuple(fixtures)


def oracle_answer(key: bytes, task_id: str) -> str:
    """Derive a repeatable private answer without storing it in repository fixtures."""
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("oracle key must contain at least 32 bytes")
    if not isinstance(task_id, str) or re.fullmatch(r"task-[0-9]{2}", task_id) is None:
        raise ValueError("task id is invalid")
    value = hmac.new(key, f"{ORACLE_SCHEMA}:{task_id}".encode(), hashlib.sha256).hexdigest()[:24]
    return f"INCYPHER{{offline_{task_id.removeprefix('task-')}_{value}}}"


def score_answer(
    *,
    expected: str,
    observed: str | None,
    source_proved: bool,
    account_history: str | None = None,
) -> Outcome:
    """Score only against the private oracle; persistent account history has no authority."""
    del account_history
    if observed is None:
        return "unverifiable"
    if not source_proved:
        return "unverifiable"
    return "correct" if hmac.compare_digest(observed, expected) else "wrong"


def _candidate_is_source_proved(value: str | None, calls: Sequence[Mapping[str, Any]]) -> bool:
    if value is None:
        return False
    digest = hashlib.sha256(value.encode()).hexdigest()
    supplied = any(
        digest in call.get("supplied_candidate_sha256s", ())
        for call in calls
        if isinstance(call, Mapping)
    )
    observed = any(
        call.get("success") is True
        and call.get("source_bound") is True
        and digest in call.get("candidate_sha256s", ())
        for call in calls
        if isinstance(call, Mapping)
    )
    return observed and not supplied


def _closed_label(value: object, default: str) -> str:
    return value if isinstance(value, str) and _CLOSED_LABEL_RE.fullmatch(value) else default


def closed_tool_error_counts(calls: Sequence[Mapping[str, Any]]) -> dict[str, object]:
    stages: Counter[str] = Counter()
    constraints: Counter[str] = Counter()
    total = 0
    untyped = 0
    for call in calls:
        if not isinstance(call, Mapping) or call.get("success") is not False:
            continue
        total += 1
        observation = call.get("host_observation")
        facts = getattr(observation, "facts", None)
        if facts is None and isinstance(observation, Mapping):
            facts = observation.get("facts")
        facts = facts if isinstance(facts, Mapping) else {}
        stage = _closed_label(facts.get("failure_stage"), "untyped")
        constraint = _closed_label(facts.get("constraint"), "untyped")
        if stage not in {"arguments", "execution", "result"}:
            stage = "untyped"
        if stage == "untyped" or constraint == "untyped":
            untyped += 1
        stages[stage] += 1
        constraints[constraint] += 1
    return {
        "total": total,
        "untyped": untyped,
        "by_stage": dict(sorted(stages.items())),
        "by_constraint": dict(sorted(constraints.items())),
    }


def _challenge(fixture: FixtureSpec) -> Challenge:
    return Challenge(
        fixture.number,
        f"Synthetic offline {fixture.family} {fixture.number:02d}",
        "misc",
        "standard",
        fixture.description,
        0,
        (),
        False,
        0,
        0,
        None,
        None,
    )


def _specialist_prompt(fixture: FixtureSpec) -> str:
    document = json.loads(build_turn_prompt(_challenge(fixture), [fixture.artifact_name], 0))
    document["agent_role"] = "specialist"
    document["comparison_policy"] = {
        "continuations": False,
        "fresh_thread": True,
        "oracle_visible": False,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"))


def _verifier_route():
    return replace(
        baseline_route(
            model=_VERIFIER_MODEL,
            effort=_VERIFIER_EFFORT,
            attempt_seconds=int(TURN_TIMEOUT_SECONDS),
        ),
        role="verifier",
        tactic="independent_source_reobservation",
        context_profile="fresh_source_only_no_candidate_carry",
        verification_recipe="fresh_source_reobservation_v1",
    )


def _verifier_prompt(fixture: FixtureSpec) -> str:
    run_id = "offline-verifier-repair"
    episode = 1
    lane = 0
    route = _verifier_route()
    memory = project_memory(
        (),
        MemoryTarget(run_id, fixture.number, episode, lane, "verifier"),
    )
    return build_turn_prompt(
        _challenge(fixture),
        [fixture.artifact_name],
        lane,
        run_id=run_id,
        episode=episode,
        control_route=route,
        same_run_memory=memory,
        agent_role="verifier",
    )


def build_verifier_repair_prompt(
    rejection_reason: str,
    remaining_seconds: float | None,
) -> str:
    """Build one candidate-free follow-up for a repairable Verifier evidence failure."""
    if rejection_reason not in _REPAIRABLE_VERIFIER_REJECTIONS:
        raise ValueError("verifier rejection is not repairable")
    if remaining_seconds is not None and (
        isinstance(remaining_seconds, bool) or remaining_seconds < 0
    ):
        raise ValueError("remaining verifier seconds are invalid")
    return json.dumps(
        {
            "label": "TRUSTED_VERIFIER_EVIDENCE_REPAIR",
            "continuation_round": 1,
            "reason": rejection_reason,
            "remaining_milliseconds": (
                None if remaining_seconds is None else max(0, int(remaining_seconds * 1000))
            ),
            "task": (
                "The prior flag-shaped hypothesis did not satisfy the Verifier evidence recipe. "
                "Continue in this same thread without echoing it or placing it in tool input. "
                "Rerun the derivation from the challenge source. If shell transformation is "
                "needed, make the transformation write its result to a workspace file without "
                "embedding the result literal, then inspect that file with a successful fixed "
                "non-run_shell source tool. Return the required JSON only after that exact "
                "source observation."
            ),
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )


def _candidate_forms(candidate: str) -> tuple[str, ...]:
    encoded = candidate.encode("utf-8")
    return (
        candidate,
        hashlib.sha256(encoded).hexdigest(),
        base64.b64encode(encoded).decode("ascii"),
        encoded.hex(),
        urllib.parse.quote(candidate, safe=""),
    )


def _current_candidate_rejection(
    candidate: str,
    challenge: Challenge,
    raw_calls: object,
) -> VerifierRejection | None:
    _, calls, complete = _normalize_tool_calls(raw_calls)
    if not complete:
        return "candidate_evidence_incomplete"
    if not candidate_is_eligible(candidate, ""):
        return "candidate_ineligible"
    digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
    supplied = any(digest in call.supplied_candidate_sha256s for call in calls)
    observed = any(
        call.success is True and call.source_bound and digest in call.candidate_sha256s
        for call in calls
    )
    if supplied:
        return "candidate_supplied"
    if not observed:
        return "candidate_unobserved"
    if not candidate_is_eligible(
        candidate,
        challenge_candidate_prose(challenge),
        source_observed=observed,
        source_supplied=supplied,
    ):
        return "candidate_ineligible"
    return None


def _whole_attempt_attestation(
    candidate: str,
    challenge: Challenge,
    raw_calls: object,
) -> VerifierRejection | None:
    """Use the durable production attestation over one complete synthetic attempt."""
    _, calls, complete = _normalize_tool_calls(raw_calls)
    with tempfile.TemporaryDirectory(prefix="rapido-offline-attestation-") as temporary:
        state = StateStore(Path(temporary) / "state.sqlite3")
        run_id = "offline-attestation"
        attempt_id = "verifier-attempt"
        try:
            state.start_run(run_id, {"offline_verifier_pilot": True})
            state.upsert_challenge(
                challenge.id,
                challenge.name,
                challenge.category,
                challenge.type,
                challenge.value,
            )
            state.start_attempt(
                attempt_id,
                run_id,
                challenge.id,
                episode=1,
                lane=0,
                model=_VERIFIER_MODEL,
                effort=_VERIFIER_EFFORT,
            )
            evidence = RunEvidence.open(state, run_id)
            evidence.commit(
                attempt_id,
                EvidenceBatch(
                    tuple(call.observation for call in calls),
                    complete=complete,
                    gap=None if complete else "provenance_incomplete",
                ),
            )
            result = evidence.attest_candidate_with_reason(
                attempt_id,
                candidate_sha256=hashlib.sha256(candidate.encode("utf-8")).hexdigest(),
                require_non_execution_observation=True,
            )
            return result.rejection_reason
        finally:
            state.close()


def _evaluate_verifier_turn(
    turn: object,
    expected: str,
    challenge: Challenge,
) -> VerifierTurnEvaluation:
    if getattr(turn, "status", None) != "completed":
        timed_out = getattr(turn, "timed_out", False) is True
        return VerifierTurnEvaluation("timeout" if timed_out else "provider_failure", None)
    try:
        finding = SolverFinding.from_message(str(getattr(turn, "text", "")))
    except SolverOutputError:
        return VerifierTurnEvaluation("solver_output", "solver_output")
    candidate = finding.candidate
    if candidate is None:
        return VerifierTurnEvaluation("no_candidate", None)
    current_calls = getattr(turn, "current_turn_tool_calls", getattr(turn, "tool_calls", None))
    rejection = _current_candidate_rejection(candidate, challenge, current_calls)
    if rejection is None:
        rejection = _whole_attempt_attestation(
            candidate,
            challenge,
            getattr(turn, "tool_calls", None),
        )
    correct = hmac.compare_digest(candidate, expected)
    if rejection is None:
        outcome: VerifierOutcome = "verified_correct" if correct else "verified_wrong"
    else:
        outcome = "rejected_correct" if correct else "rejected_wrong"
    return VerifierTurnEvaluation(outcome, rejection, candidate)


def _private_regular_file(path: Path, excluded_roots: Sequence[Path]) -> bytes:
    if not path.is_absolute():
        raise ValueError("oracle key path must be absolute")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("oracle key is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid not in {0, os.geteuid()}
    ):
        raise ValueError("oracle key must be a regular file")
    if metadata.st_mode & 0o077:
        raise ValueError("oracle key must not grant group or other access")
    for root in excluded_roots:
        resolved_root = root.resolve(strict=True)
        if resolved == resolved_root or resolved.is_relative_to(resolved_root):
            raise ValueError("oracle key must remain outside solver and authentication roots")
    payload = resolved.read_bytes()
    if not 32 <= len(payload) <= 1024:
        raise ValueError("oracle key must contain between 32 and 1024 bytes")
    return payload


def _private_directory(path: Path) -> Path:
    if not path.is_absolute():
        raise ValueError("work root must be absolute")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("work root is unavailable") from exc
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
    ):
        raise ValueError("work root must be a real directory")
    if metadata.st_mode & 0o077:
        raise ValueError("work root must not grant group or other access")
    return resolved


def _identity(value: str | None, pattern: re.Pattern[str], name: str) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if pattern.fullmatch(normalized) is None:
        raise ValueError(f"{name} is invalid")
    return normalized


def _source_identity(supplied: str | None) -> dict[str, object]:
    declared = _identity(supplied, _SHA_RE, "source SHA")
    repository = Path(__file__).resolve().parents[1]
    try:
        head = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        status = subprocess.run(
            ["git", "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        observed = _identity(head.stdout, _SHA_RE, "observed source SHA")
        if observed is None:
            raise ValueError("observed source SHA is unavailable")
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise ValueError("source identity is unavailable") from exc
    lines = [line for line in status.stdout.splitlines() if line]
    untracked = sum(line.startswith("?? ") for line in lines)
    tracked = len(lines) - untracked
    return {
        "observed": {
            "head_sha": observed,
            "worktree": "dirty" if lines else "clean",
            "tracked_change_count": tracked,
            "untracked_file_count": untracked,
        },
        "declared": {"sha": declared} if declared is not None else {"status": "unavailable"},
        "declared_matches_head": (
            hmac.compare_digest(declared, observed) if declared is not None else None
        ),
    }


def _image_identity(supplied: str | None) -> dict[str, object]:
    declared = _identity(supplied, _IMAGE_ID_RE, "image ID")
    observed = _identity(os.environ.get("RAPIDO_IMAGE_ID"), _IMAGE_ID_RE, "image ID")
    return {
        "observed": {"id": observed} if observed is not None else {"status": "unavailable"},
        "declared": {"id": declared} if declared is not None else {"status": "unavailable"},
        "declared_matches_observed": (
            hmac.compare_digest(declared, observed)
            if declared is not None and observed is not None
            else None
        ),
    }


def _safe_failure(value: object) -> str | None:
    if value is None:
        return None
    return _closed_label(value, "unknown")


def _native_usage(turn: object | None) -> dict[str, object]:
    raw = getattr(turn, "raw", None)
    if not isinstance(raw, Mapping):
        return {"status": "unavailable"}
    source: Mapping[str, object] | None = None
    for key in ("usage", "tokenUsage", "token_usage"):
        value = raw.get(key)
        if isinstance(value, Mapping):
            source = value
            break
    if source is None:
        return {"status": "unavailable"}
    aliases = {
        "input_tokens": ("input_tokens", "inputTokens"),
        "cached_input_tokens": ("cached_input_tokens", "cachedInputTokens"),
        "output_tokens": ("output_tokens", "outputTokens"),
        "reasoning_output_tokens": (
            "reasoning_output_tokens",
            "reasoningOutputTokens",
        ),
        "total_tokens": ("total_tokens", "totalTokens"),
    }
    observed: dict[str, object] = {"status": "observed"}
    for public, names in aliases.items():
        value = next((source[name] for name in names if name in source), None)
        if type(value) is int and 0 <= value <= 2**63 - 1:
            observed[public] = value
    return observed if len(observed) > 1 else {"status": "unavailable"}


async def _measure(
    client: Any,
    fixture: FixtureSpec,
    arm: Arm,
    workspace: Path,
    prompt: str,
    expected: str,
    max_workspace_bytes: int,
    fixture_elapsed_seconds: float,
) -> Measurement:
    started = time.monotonic()
    calls: list[Mapping[str, Any]] = []
    outcome: Outcome
    failure: str | None = None
    source_proved = False
    usage: Mapping[str, object] = {"status": "unavailable"}
    try:
        turn = await client.solve(
            workspace,
            prompt,
            developer_instructions=OFFLINE_DEVELOPER_INSTRUCTIONS,
            model=arm.model,
            reasoning_effort=arm.effort,
            output_schema=SOLVER_OUTPUT_SCHEMA,
            timeout=TURN_TIMEOUT_SECONDS,
            tool_registry=ToolRegistry(workspace, max_workspace_bytes=max_workspace_bytes),
        )
        usage = _native_usage(turn)
        calls = [call for call in turn.tool_calls if isinstance(call, Mapping)]
        if turn.status != "completed":
            outcome = "timeout" if turn.timed_out else "provider_failure"
            failure = (
                "timeout" if turn.timed_out else _safe_failure(turn.failure_class) or "unknown"
            )
        else:
            try:
                finding = SolverFinding.from_message(turn.text)
            except SolverOutputError:
                outcome = "unverifiable"
                failure = "solver_output"
            else:
                source_proved = _candidate_is_source_proved(finding.candidate, calls)
                outcome = score_answer(
                    expected=expected,
                    observed=finding.candidate,
                    source_proved=source_proved,
                )
    except TurnTimeoutError as exc:
        usage = _native_usage(exc.result)
        calls = [call for call in exc.result.tool_calls if isinstance(call, Mapping)]
        outcome = "timeout"
        failure = "timeout"
    except TimeoutError:
        outcome = "timeout"
        failure = "timeout"
    except ModelValidationError:
        outcome = "provider_failure"
        failure = "model_validation"
    except CodexAppError as exc:
        evidence = getattr(exc, "result", None)
        usage = _native_usage(evidence)
        raw_calls = getattr(evidence, "tool_calls", ())
        calls = [call for call in raw_calls if isinstance(call, Mapping)]
        outcome = "provider_failure"
        failure = _safe_failure(getattr(evidence, "failure_class", None)) or "native_runtime"
    except (OSError, RuntimeError, TypeError, ValueError):
        outcome = "provider_failure"
        failure = "native_runtime"
    return Measurement(
        task_id=fixture.id,
        family=fixture.family,
        arm=arm,
        outcome=outcome,
        fixture_elapsed_seconds=fixture_elapsed_seconds,
        turn_elapsed_seconds=time.monotonic() - started,
        failure_class=failure,
        source_proved=source_proved,
        tool_calls=len(calls),
        tool_errors=closed_tool_error_counts(calls),
        native_usage=usage,
    )


def _provider_failure_measurement(
    fixture: FixtureSpec,
    arm: Arm,
    *,
    fixture_elapsed_seconds: float,
    failure_class: str,
) -> Measurement:
    return Measurement(
        task_id=fixture.id,
        family=fixture.family,
        arm=arm,
        outcome="provider_failure",
        fixture_elapsed_seconds=fixture_elapsed_seconds,
        turn_elapsed_seconds=0.0,
        failure_class=failure_class,
        source_proved=False,
        tool_calls=0,
        tool_errors={"total": 0, "untyped": 0, "by_stage": {}, "by_constraint": {}},
        native_usage={"status": "unavailable"},
    )


def _mapping_calls(value: object) -> list[Mapping[str, Any]]:
    return [call for call in value if isinstance(call, Mapping)] if isinstance(value, list) else []


def _failed_verifier_measurement(
    fixture: FixtureSpec,
    arm: VerifierArm,
    *,
    fixture_elapsed_seconds: float,
    failure_class: str,
) -> VerifierMeasurement:
    failed = VerifierTurnEvaluation("provider_failure", None)
    return VerifierMeasurement(
        task_id=fixture.id,
        family=fixture.family,
        arm=arm,
        first=failed,
        final=failed,
        fixture_elapsed_seconds=fixture_elapsed_seconds,
        first_turn_seconds=0.0,
        repair_turn_seconds=0.0,
        repair_attempted=False,
        continuation_count=0,
        same_thread=True,
        continuation_prompt_candidate_free=True,
        first_tool_calls=0,
        final_tool_calls=0,
        cumulative_tool_calls=0,
        tool_errors={"total": 0, "untyped": 0, "by_stage": {}, "by_constraint": {}},
        first_native_usage={"status": "unavailable"},
        final_native_usage={"status": "unavailable"},
        failure_class=failure_class,
    )


async def _measure_verifier(
    client: Any,
    fixture: FixtureSpec,
    arm: VerifierArm,
    workspace: Path,
    prompt: str,
    expected: str,
    max_workspace_bytes: int,
    fixture_elapsed_seconds: float,
) -> VerifierMeasurement:
    started = time.monotonic()
    challenge = _challenge(fixture)
    first: VerifierTurnEvaluation | None = None
    first_finished: float | None = None
    first_thread_id: str | None = None
    first_calls: list[Mapping[str, Any]] = []
    first_usage: Mapping[str, object] = {"status": "unavailable"}
    continuation_count = 0
    continuation_prompt_candidate_free = True

    def continue_once(turn: object, remaining_seconds: float | None) -> str | None:
        nonlocal first, first_finished, first_thread_id, first_calls, first_usage
        nonlocal continuation_count, continuation_prompt_candidate_free
        if first is not None:
            return None
        first = _evaluate_verifier_turn(turn, expected, challenge)
        first_finished = time.monotonic()
        first_thread_id = getattr(turn, "thread_id", None)
        first_calls = _mapping_calls(getattr(turn, "current_turn_tool_calls", None))
        first_usage = _native_usage(turn)
        if (
            not arm.continuation
            or first.candidate is None
            or first.rejection_reason not in _REPAIRABLE_VERIFIER_REJECTIONS
        ):
            return None
        follow_up = build_verifier_repair_prompt(first.rejection_reason, remaining_seconds)
        continuation_prompt_candidate_free = not any(
            form in follow_up for form in _candidate_forms(first.candidate)
        )
        if not continuation_prompt_candidate_free:
            return None
        continuation_count = 1
        return follow_up

    result: object | None = None
    failure_class: str | None = None
    terminal_override: VerifierTurnEvaluation | None = None
    try:
        result = await client.solve(
            workspace,
            prompt,
            developer_instructions=OFFLINE_DEVELOPER_INSTRUCTIONS,
            model=_VERIFIER_MODEL,
            reasoning_effort=_VERIFIER_EFFORT,
            output_schema=SOLVER_OUTPUT_SCHEMA,
            timeout=TURN_TIMEOUT_SECONDS,
            tool_registry=ToolRegistry(workspace, max_workspace_bytes=max_workspace_bytes),
            continuation_callback=continue_once if arm.continuation else None,
        )
    except TurnTimeoutError as exc:
        result = exc.result
        terminal_override = VerifierTurnEvaluation("timeout", None)
        failure_class = "timeout"
    except TimeoutError:
        terminal_override = VerifierTurnEvaluation("timeout", None)
        failure_class = "timeout"
    except ModelValidationError:
        terminal_override = VerifierTurnEvaluation("provider_failure", None)
        failure_class = "model_validation"
    except CodexAppError as exc:
        result = getattr(exc, "result", None)
        terminal_override = VerifierTurnEvaluation("provider_failure", None)
        failure_class = _safe_failure(getattr(result, "failure_class", None)) or "native_runtime"
    except (OSError, RuntimeError, TypeError, ValueError):
        terminal_override = VerifierTurnEvaluation("provider_failure", None)
        failure_class = "native_runtime"

    finished = time.monotonic()
    if first is None:
        if terminal_override is not None:
            first = terminal_override
        elif result is not None:
            first = _evaluate_verifier_turn(result, expected, challenge)
        else:
            first = VerifierTurnEvaluation("provider_failure", None)
        first_finished = finished
        first_thread_id = getattr(result, "thread_id", None)
        first_calls = _mapping_calls(
            getattr(result, "current_turn_tool_calls", getattr(result, "tool_calls", None))
        )
        first_usage = _native_usage(result)
    final = (
        terminal_override
        if terminal_override is not None
        else _evaluate_verifier_turn(result, expected, challenge)
        if result is not None
        else VerifierTurnEvaluation("provider_failure", None)
    )
    cumulative_calls = _mapping_calls(getattr(result, "tool_calls", None))
    final_calls = _mapping_calls(
        getattr(result, "current_turn_tool_calls", getattr(result, "tool_calls", None))
    )
    assert first_finished is not None
    same_thread = continuation_count == 0 or (
        isinstance(first_thread_id, str) and first_thread_id == getattr(result, "thread_id", None)
    )
    return VerifierMeasurement(
        task_id=fixture.id,
        family=fixture.family,
        arm=arm,
        first=first,
        final=final,
        fixture_elapsed_seconds=fixture_elapsed_seconds,
        first_turn_seconds=max(0.0, first_finished - started),
        repair_turn_seconds=max(0.0, finished - first_finished) if continuation_count else 0.0,
        repair_attempted=continuation_count == 1,
        continuation_count=continuation_count,
        same_thread=same_thread,
        continuation_prompt_candidate_free=continuation_prompt_candidate_free,
        first_tool_calls=len(first_calls),
        final_tool_calls=len(final_calls),
        cumulative_tool_calls=len(cumulative_calls),
        tool_errors=closed_tool_error_counts(cumulative_calls),
        first_native_usage=first_usage,
        final_native_usage=_native_usage(result),
        failure_class=failure_class,
    )


def _aggregate(measurements: Sequence[Measurement]) -> dict[str, object]:
    result: dict[str, object] = {}
    for arm in ARMS:
        rows = [row for row in measurements if row.arm == arm]
        outcomes = Counter(row.outcome for row in rows)
        errors = Counter()
        total_tool_calls = 0
        untyped = 0
        usage_totals: Counter[str] = Counter()
        usage_observed = 0
        for row in rows:
            total_tool_calls += row.tool_calls
            error_counts = row.tool_errors
            untyped += int(error_counts["untyped"])
            for constraint, count in dict(error_counts["by_constraint"]).items():
                errors[str(constraint)] += int(count)
            if row.native_usage.get("status") == "observed":
                usage_observed += 1
                for key, value in row.native_usage.items():
                    if key != "status" and type(value) is int:
                        usage_totals[key] += value
        if usage_observed == 0:
            usage: dict[str, object] = {"status": "unavailable"}
        else:
            usage = {
                "status": "observed" if usage_observed == len(rows) else "partial",
                "turns_observed": usage_observed,
                "turns_unavailable": len(rows) - usage_observed,
                "totals": dict(sorted(usage_totals.items())),
            }
        result[arm.id] = {
            "model": arm.model,
            "effort": arm.effort,
            "tasks": len(rows),
            "outcomes": {name: outcomes.get(name, 0) for name in Outcome.__args__},
            "elapsed_seconds": round(
                sum(row.fixture_elapsed_seconds + row.turn_elapsed_seconds for row in rows), 3
            ),
            "tool_calls": total_tool_calls,
            "tool_errors_untyped": untyped,
            "tool_errors_by_constraint": dict(sorted(errors.items())),
            "native_usage": usage,
        }
    return result


def _receipt(
    config: PilotConfig,
    source: Mapping[str, object],
    image: Mapping[str, object],
    measurements: Sequence[Measurement],
    runtime: Mapping[str, object],
) -> dict[str, object]:
    return {
        "schema": RECEIPT_SCHEMA,
        "source": dict(source),
        "image": dict(image),
        "protocol": {
            "oracle_id": config.oracle_id,
            "oracle_location": "controller_only_outside_solver_workspaces",
            "post_run_scoring": True,
            "fixture_count": len(fixture_catalogue()),
            "families": sorted({fixture.family for fixture in fixture_catalogue()}),
            "role": "specialist",
            "fresh_thread_per_task": True,
            "continuations": False,
            "timeout_seconds": int(TURN_TIMEOUT_SECONDS),
            "board_enabled": False,
            "submissions_enabled": False,
            "fallback_allowed": False,
            "roster": [{"arm": arm.id, "model": arm.model, "effort": arm.effort} for arm in ARMS],
        },
        "runtime": dict(runtime),
        "results": [measurement.public() for measurement in measurements],
        "summary": _aggregate(measurements),
    }


def _verifier_summary(
    measurements: Sequence[VerifierMeasurement],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for arm in VERIFIER_ARMS:
        rows = [row for row in measurements if row.arm == arm]
        first_outcomes = Counter(row.first.outcome for row in rows)
        final_outcomes = Counter(row.final.outcome for row in rows)
        first_rejections = Counter(
            row.first.rejection_reason for row in rows if row.first.rejection_reason is not None
        )
        final_rejections = Counter(
            row.final.rejection_reason for row in rows if row.final.rejection_reason is not None
        )
        result[arm.id] = {
            "model": _VERIFIER_MODEL,
            "effort": _VERIFIER_EFFORT,
            "tasks": len(rows),
            "first_outcomes": {
                name: first_outcomes.get(name, 0) for name in VerifierOutcome.__args__
            },
            "final_outcomes": {
                name: final_outcomes.get(name, 0) for name in VerifierOutcome.__args__
            },
            "first_rejections": dict(sorted(first_rejections.items())),
            "final_rejections": dict(sorted(final_rejections.items())),
            "repair_attempts": sum(row.repair_attempted for row in rows),
            "elapsed_seconds": round(
                sum(
                    row.fixture_elapsed_seconds + row.first_turn_seconds + row.repair_turn_seconds
                    for row in rows
                ),
                3,
            ),
            "tool_calls": sum(row.cumulative_tool_calls for row in rows),
        }
    return result


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    if not ordered:
        return 0.0
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[middle]
    return (ordered[middle - 1] + ordered[middle]) / 2


def _percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[max(0, math.ceil(len(ordered) * fraction) - 1)]


def _verifier_gate(
    measurements: Sequence[VerifierMeasurement],
    runtime: Mapping[str, Mapping[str, object]],
    source: Mapping[str, object],
    image: Mapping[str, object],
    *,
    image_required: bool,
) -> dict[str, object]:
    one_shot = [row for row in measurements if row.arm.id == "one_shot"]
    repair = [row for row in measurements if row.arm.id == "evidence_repair"]
    eligible = [
        row for row in repair if row.first.rejection_reason in _REPAIRABLE_VERIFIER_REJECTIONS
    ]
    converted = [
        row for row in eligible if row.repair_attempted and row.final.outcome == "verified_correct"
    ]
    one_shot_verified = sum(row.final.outcome == "verified_correct" for row in one_shot)
    repair_first_verified = sum(row.first.outcome == "verified_correct" for row in repair)
    repair_final_verified = sum(row.final.outcome == "verified_correct" for row in repair)
    repair_spans = [row.repair_turn_seconds for row in repair if row.repair_attempted]
    verified_wrong_rows = {
        (row.task_id, row.arm.id)
        for row in measurements
        if row.first.outcome == "verified_wrong" or row.final.outcome == "verified_wrong"
    }
    unsafe_continuations = sum(
        row.repair_attempted and row.first.rejection_reason not in _REPAIRABLE_VERIFIER_REJECTIONS
        for row in repair
    )
    expected_identities = {
        (fixture.id, fixture.family, arm.id, arm.continuation)
        for fixture in fixture_catalogue()
        for arm in VERIFIER_ARMS
    }
    actual_identities = [
        (row.task_id, row.family, row.arm.id, row.arm.continuation) for row in measurements
    ]
    actual_identity_counts = Counter(actual_identities)
    missing_identities = sorted(expected_identities - set(actual_identities))
    unexpected_identities = sorted(set(actual_identities) - expected_identities)
    duplicate_identities = sorted(
        identity for identity, count in actual_identity_counts.items() if count != 1
    )
    source_observed = source.get("observed")
    source_declared = source.get("declared")
    observed_sha = source_observed.get("head_sha") if isinstance(source_observed, Mapping) else None
    declared_sha = source_declared.get("sha") if isinstance(source_declared, Mapping) else None
    source_identity_passed = (
        isinstance(source_observed, Mapping)
        and isinstance(observed_sha, str)
        and _SHA_RE.fullmatch(observed_sha) is not None
        and isinstance(declared_sha, str)
        and _SHA_RE.fullmatch(declared_sha) is not None
        and hmac.compare_digest(observed_sha, declared_sha)
        and source_observed.get("worktree") == "clean"
        and source_observed.get("tracked_change_count") == 0
        and source_observed.get("untracked_file_count") == 0
        and source.get("declared_matches_head") is True
    )
    image_observed = image.get("observed")
    image_declared = image.get("declared")
    observed_image_id = image_observed.get("id") if isinstance(image_observed, Mapping) else None
    declared_image_id = image_declared.get("id") if isinstance(image_declared, Mapping) else None
    image_identity_passed = not image_required or (
        isinstance(observed_image_id, str)
        and _IMAGE_ID_RE.fullmatch(observed_image_id) is not None
        and isinstance(declared_image_id, str)
        and _IMAGE_ID_RE.fullmatch(declared_image_id) is not None
        and hmac.compare_digest(observed_image_id, declared_image_id)
        and image.get("declared_matches_observed") is True
    )
    arm_protocol_passed = all(
        (row.arm.id == "one_shot" and not row.repair_attempted and row.continuation_count == 0)
        or (
            row.arm.id == "evidence_repair"
            and row.continuation_count in {0, 1}
            and row.repair_attempted is (row.continuation_count == 1)
        )
        for row in measurements
    )
    checks = {
        "exact_fixture_arm_identities": {
            "actual": len(measurements),
            "required": len(expected_identities),
            "missing": [list(identity) for identity in missing_identities],
            "unexpected": [list(identity) for identity in unexpected_identities],
            "duplicates": [list(identity) for identity in duplicate_identities],
            "passed": not missing_identities
            and not unexpected_identities
            and not duplicate_identities
            and len(measurements) == len(expected_identities),
        },
        "source_identity": {
            "required": True,
            "worktree": (
                source_observed.get("worktree")
                if isinstance(source_observed, Mapping)
                else "unavailable"
            ),
            "declared_matches_head": source.get("declared_matches_head"),
            "passed": source_identity_passed,
        },
        "image_identity": {
            "required": image_required,
            "status": (
                "matched"
                if image_required and image_identity_passed
                else "mismatch_or_unavailable"
                if image_required
                else "not_required"
            ),
            "declared_matches_observed": image.get("declared_matches_observed"),
            "passed": image_identity_passed,
        },
        "repair_eligible_first_turns": {
            "actual": len(eligible),
            "minimum": 4,
            "passed": len(eligible) >= 4,
        },
        "repair_conversion": {
            "actual": len(converted),
            "eligible": len(eligible),
            "minimum_fraction": 0.75,
            "passed": len(eligible) >= 4 and len(converted) / len(eligible) >= 0.75,
        },
        "added_verified_correct": {
            "actual": repair_final_verified - repair_first_verified,
            "minimum": 3,
            "passed": repair_final_verified - repair_first_verified >= 3,
        },
        "not_worse_than_one_shot": {
            "one_shot": one_shot_verified,
            "evidence_repair": repair_final_verified,
            "passed": repair_final_verified >= one_shot_verified,
        },
        "verified_wrong_task_arm_rows": {
            "actual": len(verified_wrong_rows),
            "maximum": 0,
            "passed": not verified_wrong_rows,
        },
        "unsafe_continuations": {
            "actual": unsafe_continuations,
            "maximum": 0,
            "passed": unsafe_continuations == 0,
        },
        "arm_protocol_consistency": {"passed": arm_protocol_passed},
        "same_thread": {
            "failures": sum(row.repair_attempted and not row.same_thread for row in repair),
            "passed": all(not row.repair_attempted or row.same_thread for row in repair),
        },
        "one_continuation_maximum": {
            "maximum_observed": max((row.continuation_count for row in repair), default=0),
            "passed": all(row.continuation_count <= 1 for row in repair),
        },
        "candidate_free_continuation_prompts": {
            "failures": sum(not row.continuation_prompt_candidate_free for row in repair),
            "passed": all(row.continuation_prompt_candidate_free for row in repair),
        },
        "provider_failures_or_timeouts": {
            "actual": sum(
                row.final.outcome in {"provider_failure", "timeout"} for row in measurements
            ),
            "maximum": 0,
            "passed": all(
                row.final.outcome not in {"provider_failure", "timeout"} for row in measurements
            ),
        },
        "exact_runtime_and_cleanup": {
            "expected_arms": sorted(arm.id for arm in VERIFIER_ARMS),
            "actual_arms": sorted(runtime),
            "passed": set(runtime) == {arm.id for arm in VERIFIER_ARMS}
            and all(
                row.get("model") == _VERIFIER_MODEL
                and row.get("effort") == _VERIFIER_EFFORT
                and row.get("status") == "completed"
                and isinstance(row.get("spans"), Mapping)
                and row["spans"].get("cleanup", {}).get("status") == "completed"
                for row in runtime.values()
            ),
        },
        "repair_elapsed_median": {
            "actual_seconds": round(_median(repair_spans), 3),
            "maximum_seconds": 120,
            "passed": bool(repair_spans) and _median(repair_spans) <= 120,
        },
        "repair_elapsed_p90": {
            "actual_seconds": round(_percentile(repair_spans, 0.9), 3),
            "maximum_seconds": 240,
            "passed": bool(repair_spans) and _percentile(repair_spans, 0.9) <= 240,
        },
        "sanitized_receipt": {"passed": True},
    }
    passed = all(bool(check["passed"]) for check in checks.values())
    underpowered_exemptions = {
        "repair_eligible_first_turns",
        "repair_conversion",
        "added_verified_correct",
        "repair_elapsed_median",
        "repair_elapsed_p90",
    }
    otherwise_clean = all(
        bool(check["passed"])
        for name, check in checks.items()
        if name not in underpowered_exemptions
    )
    return {
        "status": (
            "passed"
            if passed
            else "inconclusive"
            if len(eligible) < 4 and otherwise_clean
            else "failed"
        ),
        "checks": checks,
    }


def _verifier_receipt(
    config: PilotConfig,
    source: Mapping[str, object],
    image: Mapping[str, object],
    measurements: Sequence[VerifierMeasurement],
    runtime: Mapping[str, Mapping[str, object]],
) -> dict[str, object]:
    return {
        "schema": VERIFIER_REPAIR_RECEIPT_SCHEMA,
        "source": dict(source),
        "image": dict(image),
        "protocol": {
            "experiment": VERIFIER_REPAIR_EXPERIMENT,
            "oracle_id": config.oracle_id,
            "oracle_location": "controller_only_outside_solver_workspaces",
            "post_run_scoring": True,
            "fixture_count": len(fixture_catalogue()),
            "families": sorted({fixture.family for fixture in fixture_catalogue()}),
            "role": "verifier",
            "fresh_thread_per_task_and_arm": True,
            "repair_same_thread": True,
            "repair_continuation_limit": 1,
            "repairable_rejections": sorted(_REPAIRABLE_VERIFIER_REJECTIONS),
            "whole_attempt_taint": True,
            "fixed_non_run_shell_observation_required": True,
            "prompt_parity": {
                "offline_developer_authorization_preamble_differs_from_production": True,
                "common_developer_rules_match_production": True,
                "verifier_task_and_route_match_production": True,
            },
            "source_identity_required": True,
            "image_identity_required": config.image_id is not None,
            "timeout_seconds_cumulative": int(TURN_TIMEOUT_SECONDS),
            "board_enabled": False,
            "submissions_enabled": False,
            "fallback_allowed": False,
            "roster": [
                {
                    "arm": arm.id,
                    "model": _VERIFIER_MODEL,
                    "effort": _VERIFIER_EFFORT,
                    "continuation": arm.continuation,
                }
                for arm in VERIFIER_ARMS
            ],
        },
        "runtime": {name: dict(row) for name, row in runtime.items()},
        "results": [measurement.public() for measurement in measurements],
        "summary": _verifier_summary(measurements),
        "gate": _verifier_gate(
            measurements,
            runtime,
            source,
            image,
            image_required=config.image_id is not None,
        ),
    }


async def run_pilot(
    config: PilotConfig,
    *,
    client_factory: Callable[..., Any] = CodexAppClient,
) -> dict[str, object]:
    """Run one fresh-thread matched pair per fixture and return only sanitized data."""
    validate_codex_home(config.codex_home)
    work_root = _private_directory(config.work_root)
    key = _private_regular_file(
        config.oracle_key_file,
        (
            work_root,
            config.codex_home.resolve(strict=True),
            Path(__file__).resolve().parents[1],
        ),
    )
    if not isinstance(config.oracle_id, str) or _ORACLE_ID_RE.fullmatch(config.oracle_id) is None:
        raise ValueError("oracle id must be a closed label")
    if not 1 <= config.max_workspace_bytes <= MAX_WORKSPACE_BYTES:
        raise ValueError("workspace byte limit is invalid")
    source = _source_identity(config.source_sha)
    image = _image_identity(config.image_id)
    measurements: list[Measurement] = []
    runtime: dict[str, dict[str, object]] = {
        arm.id: {
            "model": arm.model,
            "effort": arm.effort,
            "status": "pending",
            "failure_class": None,
            "spans": {
                "startup": {"status": "not_run", "elapsed_seconds": 0.0},
                "model_validation": {"status": "not_run", "elapsed_seconds": 0.0},
                "cleanup": {"status": "not_run", "elapsed_seconds": 0.0},
            },
        }
        for arm in ARMS
    }

    with tempfile.TemporaryDirectory(prefix="rapido-offline-oracle-", dir=work_root) as temporary:
        run_root = Path(temporary)
        run_root.chmod(0o700)
        clients: dict[Arm, Any] = {}

        async def start_arm(arm: Arm) -> None:
            arm_root = run_root / arm.id
            arm_root.mkdir(mode=0o700)
            row = runtime[arm.id]
            spans = row["spans"]
            assert isinstance(spans, dict)
            started = time.monotonic()
            try:
                client = client_factory(
                    env={
                        "CODEX_HOME": str(config.codex_home),
                        "HOME": str(config.codex_home),
                        "PATH": "/usr/local/bin:/usr/bin:/bin",
                        "TERM": "dumb",
                        "NO_COLOR": "1",
                    },
                    binary=config.codex_binary,
                    cwd=arm_root,
                    max_workspace_bytes=config.max_workspace_bytes,
                )
                if any(client is existing for existing in clients.values()):
                    raise RuntimeError("client factory reused a native process")
                clients[arm] = client
                await asyncio.wait_for(client.start(), timeout=TURN_TIMEOUT_SECONDS)
            except asyncio.CancelledError:
                raise
            except (CodexAppError, OSError, TimeoutError, RuntimeError, TypeError, ValueError):
                spans["startup"] = {
                    "status": "failed",
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                }
                row["status"] = "failed"
                row["failure_class"] = "startup"
                return
            spans["startup"] = {
                "status": "completed",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            validated = time.monotonic()
            try:
                descriptor = await asyncio.wait_for(
                    client.validate_model(arm.model, arm.effort),
                    timeout=TURN_TIMEOUT_SECONDS,
                )
                if getattr(descriptor, "name", None) != arm.model or arm.effort not in getattr(
                    descriptor, "reasoning_efforts", ()
                ):
                    raise ModelValidationError(
                        "native model validation did not retain the exact roster"
                    )
            except asyncio.CancelledError:
                raise
            except (CodexAppError, OSError, TimeoutError, RuntimeError, TypeError, ValueError):
                spans["model_validation"] = {
                    "status": "failed",
                    "elapsed_seconds": round(time.monotonic() - validated, 3),
                }
                row["status"] = "failed"
                row["failure_class"] = "model_validation"
                return
            spans["model_validation"] = {
                "status": "completed",
                "elapsed_seconds": round(time.monotonic() - validated, 3),
            }
            row["status"] = "ready"

        async def close_arm(arm: Arm) -> None:
            row = runtime[arm.id]
            spans = row["spans"]
            assert isinstance(spans, dict)
            client = clients.get(arm)
            if client is None:
                return
            started = time.monotonic()
            try:
                await asyncio.wait_for(client.close(), timeout=TURN_TIMEOUT_SECONDS)
            except asyncio.CancelledError:
                raise
            except (CodexAppError, OSError, TimeoutError, RuntimeError, TypeError, ValueError):
                spans["cleanup"] = {
                    "status": "failed",
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                }
                row["status"] = "failed"
                row["failure_class"] = row["failure_class"] or "cleanup"
                return
            spans["cleanup"] = {
                "status": "completed",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            if row["status"] == "ready":
                row["status"] = "completed"

        try:
            # Both native clients share one fresh CODEX_HOME. Its first-use SQLite
            # bootstrap is not concurrency-safe, so initialize each process before
            # running the paired fixture turns concurrently below.
            for arm in ARMS:
                await start_arm(arm)

            for fixture in fixture_catalogue():
                expected = oracle_answer(key, fixture.id)
                material = fixture.material(expected)
                prompt = _specialist_prompt(fixture)
                prepared: dict[Arm, tuple[Path, float]] = {}
                pair: dict[Arm, Measurement] = {}
                for arm in ARMS:
                    setup_started = time.monotonic()
                    workspace = run_root / arm.id / fixture.id
                    try:
                        workspace.mkdir(mode=0o700, parents=True)
                        artifact = workspace / fixture.artifact_name
                        artifact.write_bytes(material)
                        artifact.chmod(0o600)
                    except OSError:
                        pair[arm] = _provider_failure_measurement(
                            fixture,
                            arm,
                            fixture_elapsed_seconds=time.monotonic() - setup_started,
                            failure_class="fixture_setup",
                        )
                        continue
                    prepared[arm] = (workspace, time.monotonic() - setup_started)

                tasks: dict[Arm, asyncio.Task[Measurement]] = {}
                for arm in ARMS:
                    if arm in pair:
                        continue
                    workspace, setup_elapsed = prepared[arm]
                    client = clients.get(arm)
                    failure = runtime[arm.id]["failure_class"]
                    if client is None or runtime[arm.id]["status"] != "ready":
                        pair[arm] = _provider_failure_measurement(
                            fixture,
                            arm,
                            fixture_elapsed_seconds=setup_elapsed,
                            failure_class=str(failure or "startup"),
                        )
                        continue
                    tasks[arm] = asyncio.create_task(
                        _measure(
                            client,
                            fixture,
                            arm,
                            workspace,
                            prompt,
                            expected,
                            config.max_workspace_bytes,
                            setup_elapsed,
                        )
                    )
                if tasks:
                    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
                    for arm, result in zip(tasks, results, strict=True):
                        if isinstance(result, asyncio.CancelledError):
                            raise result
                        if isinstance(result, BaseException):
                            _, setup_elapsed = prepared[arm]
                            pair[arm] = _provider_failure_measurement(
                                fixture,
                                arm,
                                fixture_elapsed_seconds=setup_elapsed,
                                failure_class="native_runtime",
                            )
                        else:
                            pair[arm] = result
                measurements.extend(pair[arm] for arm in ARMS)
        finally:
            await asyncio.gather(*(close_arm(arm) for arm in ARMS))

    return _receipt(config, source, image, measurements, runtime)


async def run_verifier_repair_pilot(
    config: PilotConfig,
    *,
    client_factory: Callable[..., Any] = CodexAppClient,
) -> dict[str, object]:
    """Compare one-shot verification with one candidate-free same-thread repair."""
    validate_codex_home(config.codex_home)
    work_root = _private_directory(config.work_root)
    key = _private_regular_file(
        config.oracle_key_file,
        (
            work_root,
            config.codex_home.resolve(strict=True),
            Path(__file__).resolve().parents[1],
        ),
    )
    if not isinstance(config.oracle_id, str) or _ORACLE_ID_RE.fullmatch(config.oracle_id) is None:
        raise ValueError("oracle id must be a closed label")
    if not 1 <= config.max_workspace_bytes <= MAX_WORKSPACE_BYTES:
        raise ValueError("workspace byte limit is invalid")
    source = _source_identity(config.source_sha)
    image = _image_identity(config.image_id)
    measurements: list[VerifierMeasurement] = []
    runtime: dict[str, dict[str, object]] = {
        arm.id: {
            "model": _VERIFIER_MODEL,
            "effort": _VERIFIER_EFFORT,
            "status": "pending",
            "failure_class": None,
            "spans": {
                "startup": {"status": "not_run", "elapsed_seconds": 0.0},
                "model_validation": {"status": "not_run", "elapsed_seconds": 0.0},
                "cleanup": {"status": "not_run", "elapsed_seconds": 0.0},
            },
        }
        for arm in VERIFIER_ARMS
    }

    with tempfile.TemporaryDirectory(
        prefix="rapido-offline-verifier-repair-", dir=work_root
    ) as temporary:
        run_root = Path(temporary)
        run_root.chmod(0o700)
        clients: dict[VerifierArm, Any] = {}

        async def start_arm(arm: VerifierArm) -> None:
            arm_root = run_root / arm.id
            arm_root.mkdir(mode=0o700)
            row = runtime[arm.id]
            spans = row["spans"]
            assert isinstance(spans, dict)
            started = time.monotonic()
            try:
                client = client_factory(
                    env={
                        "CODEX_HOME": str(config.codex_home),
                        "HOME": str(config.codex_home),
                        "PATH": "/usr/local/bin:/usr/bin:/bin",
                        "TERM": "dumb",
                        "NO_COLOR": "1",
                    },
                    binary=config.codex_binary,
                    cwd=arm_root,
                    max_workspace_bytes=config.max_workspace_bytes,
                )
                if any(client is existing for existing in clients.values()):
                    raise RuntimeError("client factory reused a native process")
                clients[arm] = client
                await asyncio.wait_for(client.start(), timeout=TURN_TIMEOUT_SECONDS)
            except asyncio.CancelledError:
                raise
            except (CodexAppError, OSError, TimeoutError, RuntimeError, TypeError, ValueError):
                spans["startup"] = {
                    "status": "failed",
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                }
                row["status"] = "failed"
                row["failure_class"] = "startup"
                return
            spans["startup"] = {
                "status": "completed",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            validated = time.monotonic()
            try:
                descriptor = await asyncio.wait_for(
                    client.validate_model(_VERIFIER_MODEL, _VERIFIER_EFFORT),
                    timeout=TURN_TIMEOUT_SECONDS,
                )
                if getattr(
                    descriptor, "name", None
                ) != _VERIFIER_MODEL or _VERIFIER_EFFORT not in getattr(
                    descriptor, "reasoning_efforts", ()
                ):
                    raise ModelValidationError(
                        "native model validation did not retain the exact verifier roster"
                    )
            except asyncio.CancelledError:
                raise
            except (CodexAppError, OSError, TimeoutError, RuntimeError, TypeError, ValueError):
                spans["model_validation"] = {
                    "status": "failed",
                    "elapsed_seconds": round(time.monotonic() - validated, 3),
                }
                row["status"] = "failed"
                row["failure_class"] = "model_validation"
                return
            spans["model_validation"] = {
                "status": "completed",
                "elapsed_seconds": round(time.monotonic() - validated, 3),
            }
            row["status"] = "ready"

        async def close_arm(arm: VerifierArm) -> None:
            row = runtime[arm.id]
            spans = row["spans"]
            assert isinstance(spans, dict)
            client = clients.get(arm)
            if client is None:
                return
            started = time.monotonic()
            try:
                await asyncio.wait_for(client.close(), timeout=TURN_TIMEOUT_SECONDS)
            except asyncio.CancelledError:
                raise
            except (CodexAppError, OSError, TimeoutError, RuntimeError, TypeError, ValueError):
                spans["cleanup"] = {
                    "status": "failed",
                    "elapsed_seconds": round(time.monotonic() - started, 3),
                }
                row["status"] = "failed"
                row["failure_class"] = row["failure_class"] or "cleanup"
                return
            spans["cleanup"] = {
                "status": "completed",
                "elapsed_seconds": round(time.monotonic() - started, 3),
            }
            if row["status"] == "ready":
                row["status"] = "completed"

        try:
            # Both native clients share one fresh CODEX_HOME. Its first-use SQLite
            # bootstrap is not concurrency-safe, so initialize each process before
            # running the paired fixture turns concurrently below.
            for arm in VERIFIER_ARMS:
                await start_arm(arm)
            for fixture in fixture_catalogue():
                expected = oracle_answer(key, fixture.id)
                material = fixture.material(expected)
                prompt = _verifier_prompt(fixture)
                prepared: dict[VerifierArm, tuple[Path, float]] = {}
                pair: dict[VerifierArm, VerifierMeasurement] = {}
                for arm in VERIFIER_ARMS:
                    setup_started = time.monotonic()
                    workspace = run_root / arm.id / fixture.id
                    try:
                        workspace.mkdir(mode=0o700, parents=True)
                        artifact = workspace / fixture.artifact_name
                        artifact.write_bytes(material)
                        artifact.chmod(0o600)
                    except OSError:
                        pair[arm] = _failed_verifier_measurement(
                            fixture,
                            arm,
                            fixture_elapsed_seconds=time.monotonic() - setup_started,
                            failure_class="fixture_setup",
                        )
                        continue
                    prepared[arm] = (workspace, time.monotonic() - setup_started)

                tasks: dict[VerifierArm, asyncio.Task[VerifierMeasurement]] = {}
                for arm in VERIFIER_ARMS:
                    if arm in pair:
                        continue
                    workspace, setup_elapsed = prepared[arm]
                    client = clients.get(arm)
                    failure = runtime[arm.id]["failure_class"]
                    if client is None or runtime[arm.id]["status"] != "ready":
                        pair[arm] = _failed_verifier_measurement(
                            fixture,
                            arm,
                            fixture_elapsed_seconds=setup_elapsed,
                            failure_class=str(failure or "startup"),
                        )
                        continue
                    tasks[arm] = asyncio.create_task(
                        _measure_verifier(
                            client,
                            fixture,
                            arm,
                            workspace,
                            prompt,
                            expected,
                            config.max_workspace_bytes,
                            setup_elapsed,
                        )
                    )
                if tasks:
                    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
                    for arm, result in zip(tasks, results, strict=True):
                        if isinstance(result, asyncio.CancelledError):
                            raise result
                        if isinstance(result, BaseException):
                            _, setup_elapsed = prepared[arm]
                            pair[arm] = _failed_verifier_measurement(
                                fixture,
                                arm,
                                fixture_elapsed_seconds=setup_elapsed,
                                failure_class="native_runtime",
                            )
                        else:
                            pair[arm] = result
                measurements.extend(pair[arm] for arm in VERIFIER_ARMS)
        finally:
            await asyncio.gather(*(close_arm(arm) for arm in VERIFIER_ARMS))

    receipt = _verifier_receipt(config, source, image, measurements, runtime)
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
    for fixture in fixture_catalogue():
        expected = oracle_answer(key, fixture.id)
        if any(form in encoded for form in _candidate_forms(expected)):
            raise RuntimeError("sanitized verifier receipt retained private candidate material")
    return receipt


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument(
        "--experiment",
        choices=(MODEL_COMPARISON_EXPERIMENT, VERIFIER_REPAIR_EXPERIMENT),
        default=MODEL_COMPARISON_EXPERIMENT,
    )
    result.add_argument("--codex-binary", required=True)
    result.add_argument("--codex-home", required=True, type=Path)
    result.add_argument("--work-root", required=True, type=Path)
    result.add_argument("--oracle-key-file", required=True, type=Path)
    result.add_argument("--oracle-id", default=ORACLE_SCHEMA)
    result.add_argument("--source-sha")
    result.add_argument("--image-id")
    result.add_argument("--max-workspace-bytes", type=int, default=MAX_WORKSPACE_BYTES)
    return result


def main() -> int:
    arguments = parser().parse_args()
    config = PilotConfig(
        codex_binary=arguments.codex_binary,
        codex_home=arguments.codex_home,
        work_root=arguments.work_root,
        oracle_key_file=arguments.oracle_key_file,
        source_sha=arguments.source_sha,
        image_id=arguments.image_id,
        oracle_id=arguments.oracle_id,
        max_workspace_bytes=arguments.max_workspace_bytes,
    )
    pilot = (
        run_verifier_repair_pilot(config)
        if arguments.experiment == VERIFIER_REPAIR_EXPERIMENT
        else run_pilot(config)
    )
    print(json.dumps(asyncio.run(pilot), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
