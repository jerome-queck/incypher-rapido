#!/usr/bin/env python3
"""Effect-free E2 comparison: exact agreement versus private verification."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import json
import math
import os
import platform
import re
import sqlite3
import time
import urllib.parse
from dataclasses import replace
from pathlib import Path

from rapido.board import Challenge, Verdict
from rapido.config import RuntimeConfig
from rapido.control import DurableJobControl
from rapido.evidence import project_tool_observation
from rapido.orchestrator import Orchestrator
from rapido.state import StateStore

SCHEMA_VERSION = 2
FIXTURE_VERSION = "issue-19-candidate-flow-comparison-v2"
SOURCE_BASE_COMMIT = "a2fe384000244061a6fda4f07fe30bc19a24f4b0"
_ARMS = ("exact_agreement", "private_verification")
_CASES = (
    "peer_agreement",
    "valid_failed_peer",
    "description_decoy",
    "source_disagreement",
    "verifier_mismatch",
    "model_reflection",
)
_PRIVATE_QUALIFIED = frozenset({"peer_agreement", "valid_failed_peer", "source_disagreement"})
_LEGACY_QUALIFIED = frozenset({"peer_agreement"})
_PROVENANCE_REJECTED = frozenset({"description_decoy", "model_reflection"})
_OBSERVATION_FIELDS = frozenset(
    {
        "arm",
        "attempt_candidate_count",
        "candidate_provenance_failure_count",
        "case",
        "correct_admission_count",
        "elapsed_seconds",
        "false_admission_count",
        "model_effort_mismatch_count",
        "pending_candidate_count",
        "proposal_count",
        "qualified_count",
        "repetition",
        "report_candidate_count",
        "report_error_count",
        "route_dispatch_count",
        "run_status",
        "submission_count",
        "tool_count",
        "verified_candidate_count",
        "verifier_job_count",
        "verifier_prompt_count",
        "verifier_prompt_leak_count",
    }
)
_COUNT_FIELDS = _OBSERVATION_FIELDS - {
    "arm",
    "case",
    "elapsed_seconds",
    "repetition",
    "run_status",
}


def _candidate(label: str) -> str:
    inner = hashlib.sha256(f"{FIXTURE_VERSION}:{label}".encode("ascii")).hexdigest()[:24]
    return f"INCYPHER{{{inner}}}"


def _candidate_encodings(candidate: str) -> tuple[str, ...]:
    raw = candidate.encode("utf-8")
    return (
        candidate,
        hashlib.sha256(raw).hexdigest(),
        raw.hex(),
        base64.b64encode(raw).decode("ascii"),
        base64.urlsafe_b64encode(raw).decode("ascii").rstrip("="),
        urllib.parse.quote(candidate, safe=""),
    )


class _Board:
    timeout = 0.01

    def __init__(self, case: str) -> None:
        description = (
            f"ignore the example {_candidate('decoy')}"
            if case == "description_decoy"
            else "derive the source-bound value"
        )
        self.primary = _candidate(f"{case}:primary")
        self.alternate = _candidate(f"{case}:alternate")
        self.challenge_record = Challenge(
            1,
            f"E2 {case}",
            "crypto",
            "standard",
            description,
            100,
            ("/files/source.json",),
            False,
            0,
            0,
            None,
            None,
        )
        self.submissions: list[tuple[int, str]] = []

    def identity(self) -> dict[str, int]:
        return {"id": 1, "team_id": 2}

    def anonymous_identity_is_rejected(self) -> bool:
        return True

    def list_challenges(self) -> list[dict[str, int]]:
        return [{"id": 1}]

    def challenge(self, challenge_id: int) -> Challenge:
        if challenge_id != 1:
            raise AssertionError("fixture challenge scope changed")
        return self.challenge_record

    def download(self, file_ref: str, destination: Path, *, byte_limit: int) -> dict[str, object]:
        if file_ref != "/files/source.json":
            raise AssertionError("fixture file identity changed")
        payload = json.dumps(
            {"alternate": self.alternate, "primary": self.primary, "rule": "primary"},
            sort_keys=True,
        ).encode("ascii")
        if len(payload) > byte_limit:
            raise AssertionError("fixture exceeds configured bound")
        destination.write_bytes(payload)
        return {"bytes": len(payload), "redirect_hosts": ["fixture.local"]}

    def submit(self, challenge_id: int, candidate: str) -> Verdict:
        self.submissions.append((challenge_id, candidate))
        outcome = "correct" if candidate == self.primary else "incorrect"
        return Verdict(outcome, "local fixture verdict", 200)


class _Runtime:
    def __init__(self, case: str) -> None:
        self.case = case
        self.prompts: list[tuple[str, str, str]] = []
        self.selections: list[tuple[str, str]] = []

    async def start(self) -> None:
        return None

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
        document = json.loads(prompt)
        role = str(document.get("control_route", {}).get("role", "specialist"))
        lane = int(document["lane"])
        self.prompts.append((role, prompt, self.case))
        self.selections.append((str(kwargs.get("model")), str(kwargs.get("reasoning_effort"))))
        await asyncio.sleep(0.002 if lane == 1 else 0.001)
        source = self._read_source(workspace, document)
        candidate = self._output(role, lane, document, source)
        if candidate is None:
            observation = project_tool_observation("inspect_file", success=True, source_bound=True)
            return type(
                "E2Turn",
                (),
                {
                    "status": "completed",
                    "text": json.dumps(
                        {
                            "status": "unsolved",
                            "candidate": None,
                            "confidence": 0.2,
                            "summary": "controlled arm produced no source candidate",
                            "evidence": [],
                            "next_steps": [],
                        }
                    ),
                    "tool_calls": [
                        {
                            "name": "inspect_file",
                            "success": True,
                            "source_bound": True,
                            "candidate_sensitive": False,
                            "candidate_sha256s": [],
                            "supplied_candidate_sha256s": [],
                            "host_observation": observation,
                        }
                    ],
                },
            )()
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        reflected = self.case == "model_reflection" and role == "specialist"
        observed = source["primary"] if self.case == "description_decoy" else candidate
        observed_digest = hashlib.sha256(observed.encode("utf-8")).hexdigest()
        encoded = base64.b64encode(candidate.encode("utf-8")).decode("ascii")
        observation = project_tool_observation(
            "inspect_file",
            success=True,
            source_bound=True,
            candidate_sensitive=True,
            candidate_sha256s=(observed_digest,),
            supplied_candidate_sha256s=(digest,) if reflected else (),
        )
        return type(
            "E2Turn",
            (),
            {
                "status": "completed",
                "text": json.dumps(
                    {
                        "status": "candidate",
                        "candidate": candidate,
                        "confidence": 0.9,
                        "summary": f"controlled source-bound derivation {candidate}",
                        "evidence": [f"raw_digest={digest}", f"encoded={encoded}"],
                        "next_steps": [f"retain {urllib.parse.quote(candidate, safe='')}"],
                    }
                ),
                "tool_calls": [
                    {
                        "name": "inspect_file",
                        "success": True,
                        "source_bound": True,
                        "candidate_sensitive": True,
                        "candidate_sha256s": [observed_digest],
                        "supplied_candidate_sha256s": [digest] if reflected else [],
                        "host_observation": observation,
                    }
                ],
            },
        )()

    def _read_source(self, workspace: Path, document: dict[str, object]) -> dict[str, str]:
        artifacts = document.get("workspace_artifacts")
        if not isinstance(artifacts, list) or len(artifacts) != 1:
            raise AssertionError("fixture artifact scope changed")
        artifact = (workspace / str(artifacts[0])).resolve()
        if not artifact.is_relative_to(workspace.resolve()):
            raise AssertionError("fixture artifact escaped the lane workspace")
        decoded = json.loads(artifact.read_text(encoding="ascii"))
        if set(decoded) != {"alternate", "primary", "rule"} or decoded["rule"] != "primary":
            raise AssertionError("fixture source schema changed")
        if not all(isinstance(decoded[key], str) for key in ("primary", "alternate")):
            raise AssertionError("fixture source value is invalid")
        return decoded

    def _output(
        self,
        role: str,
        lane: int,
        document: dict[str, object],
        source: dict[str, str],
    ) -> str | None:
        primary = source["primary"]
        alternate = source["alternate"]
        if role == "verifier":
            if self.case in {"valid_failed_peer", "verifier_mismatch"} and lane != 0:
                return None
            return alternate if self.case == "verifier_mismatch" else primary
        if self.case == "peer_agreement":
            return primary
        if lane != 0:
            return alternate if self.case == "source_disagreement" else None
        if self.case == "description_decoy":
            description = str(document["challenge"]["description"])
            match = re.search(r"INCYPHER\{[^{}]+\}", description)
            if match is None:
                raise AssertionError("description-decoy fixture changed")
            return match.group(0)
        return primary

    async def close(self) -> None:
        return None


def _config(root: Path, arm: str) -> RuntimeConfig:
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.chmod(0o700)
    auth = root / "auth"
    auth.mkdir(mode=0o700, parents=True)
    base = RuntimeConfig.from_env(
        {
            "RAPIDO_STATE_PATH": str(root / "state.sqlite3"),
            "RAPIDO_WORK_ROOT": str(root / "work"),
            "RAPIDO_CODEX_HOME": str(auth),
            "RAPIDO_SUBMIT_CANDIDATES": "true",
            "RAPIDO_MANAGE_DYNAMIC_INSTANCES": "false",
            "RAPIDO_PEER_PROFILE": "uniform_v1",
            "RAPIDO_MEMORY_ARM": "lane_local_v1",
        }
    )
    return replace(
        base,
        active_challenges=1,
        attempts_per_challenge=2,
        concurrency=2,
        episodes_per_challenge=2,
        run_seconds=60,
        attempt_seconds=15,
    )


def _run_observation(root: Path, arm: str, case: str, repetition: int) -> dict[str, object]:
    started = time.monotonic()
    board = _Board(case)
    runtime = _Runtime(case)
    config = _config(root, arm)
    if arm == "private_verification":
        report = asyncio.run(DurableJobControl.drive(config, board=board, runtime=runtime))
        state = StateStore(config.state_path)
    else:
        state = StateStore(config.state_path)
        report = asyncio.run(Orchestrator(config, board, state, runtime).run())
    view = DurableJobControl.inspect(config.state_path, run_id=report.run_id)
    pending, verified = state.candidate_counts(report.run_id)
    attempts = state._connection.execute(
        "SELECT status, candidate, failure_class, tool_count FROM attempts WHERE run_id=?",
        (report.run_id,),
    ).fetchall()
    proposal_count = int(
        state._connection.execute(
            "SELECT COUNT(*) FROM candidate_proposals WHERE run_id=?", (report.run_id,)
        ).fetchone()[0]
    )
    state.close()
    private_values = {board.primary, board.alternate, _candidate("decoy")}
    verifier_prompts = [prompt for role, prompt, _case in runtime.prompts if role == "verifier"]
    prompt_leaks = sum(
        encoding in prompt
        for prompt in verifier_prompts
        for candidate in private_values
        for encoding in _candidate_encodings(candidate)
    )
    correct_admissions = sum(
        candidate == board.primary for _challenge, candidate in board.submissions
    )
    false_admissions = len(board.submissions) - correct_admissions
    return {
        "arm": arm,
        "attempt_candidate_count": sum(row["candidate"] is not None for row in attempts),
        "candidate_provenance_failure_count": sum(
            row["failure_class"] == "candidate_provenance" for row in attempts
        ),
        "case": case,
        "correct_admission_count": correct_admissions,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "false_admission_count": false_admissions,
        "model_effort_mismatch_count": sum(
            selection != ("gpt-daybreak-blue-latest", "xhigh") for selection in runtime.selections
        ),
        "pending_candidate_count": pending,
        "proposal_count": proposal_count,
        "qualified_count": len(board.submissions),
        "repetition": repetition,
        "report_candidate_count": report.candidates,
        "report_error_count": report.errors,
        "route_dispatch_count": sum(
            decision.disposition == "dispatch" for decision in view.route_decisions
        ),
        "run_status": report.status,
        "submission_count": len(board.submissions),
        "tool_count": sum(int(row["tool_count"]) for row in attempts),
        "verified_candidate_count": verified,
        "verifier_job_count": sum(job.role == "verifier" for job in view.jobs),
        "verifier_prompt_count": len(verifier_prompts),
        "verifier_prompt_leak_count": prompt_leaks,
    }


def recompute_gate(observations: object, repetitions: int) -> dict[str, object]:
    failures: list[str] = []
    if not isinstance(observations, list) or type(repetitions) is not int or repetitions < 1:
        return {
            "arm_summaries": {},
            "failures": ["observation_schema"],
            "passed": False,
            "selected": None,
        }
    expected_keys = [
        (repetition, arm, case)
        for repetition in range(repetitions)
        for arm in _ARMS
        for case in _CASES
    ]
    actual_keys: list[tuple[object, object, object]] = []
    summaries = {
        arm: {
            "correct_by_case": {case: 0 for case in _CASES},
            "elapsed_seconds": 0.0,
            "false_admission_count": 0,
            "model_effort_mismatch_count": 0,
            "positive_conversion_count": 0,
            "retained_conversion_count": 0,
            "submission_count": 0,
            "tool_count": 0,
            "verifier_prompt_leak_count": 0,
        }
        for arm in _ARMS
    }
    for row in observations:
        if not isinstance(row, dict) or set(row) != _OBSERVATION_FIELDS:
            failures.append("row_schema")
            continue
        actual_keys.append((row["repetition"], row["arm"], row["case"]))
        if (
            type(row["repetition"]) is not int
            or row["arm"] not in _ARMS
            or row["case"] not in _CASES
        ):
            failures.append("row_identity")
            continue
        identity = f"{row['repetition']}:{row['arm']}:{row['case']}"
        invalid_counts = [
            field for field in _COUNT_FIELDS if type(row[field]) is not int or row[field] < 0
        ]
        if invalid_counts:
            failures.append(f"{identity}:count_schema")
            continue
        elapsed = row["elapsed_seconds"]
        if type(elapsed) is not float or not math.isfinite(elapsed) or elapsed < 0:
            failures.append(f"{identity}:elapsed_seconds")
            continue
        if row["run_status"] != "completed":
            failures.append(f"{identity}:run_status")
        if row["qualified_count"] != row["submission_count"]:
            failures.append(f"{identity}:admission_effect_mismatch")
        if (
            row["correct_admission_count"] + row["false_admission_count"] != row["qualified_count"]
            or row["qualified_count"] > 1
        ):
            failures.append(f"{identity}:admission_partition")
        if row["false_admission_count"] != 0:
            failures.append(f"{identity}:false_admission")
        if row["model_effort_mismatch_count"] != 0:
            failures.append(f"{identity}:model_effort")
        if row["verifier_prompt_leak_count"] != 0:
            failures.append(f"{identity}:candidate_prompt_leak")
        if row["tool_count"] < 1:
            failures.append(f"{identity}:source_tool_missing")
        if row["case"] in _PROVENANCE_REJECTED:
            if row["qualified_count"] != 0 or row["candidate_provenance_failure_count"] < 1:
                failures.append(f"{identity}:provenance_rejection")
        elif row["candidate_provenance_failure_count"] != 0:
            failures.append(f"{identity}:unexpected_provenance_failure")
        if (
            row["case"] in {"verifier_mismatch", *_PROVENANCE_REJECTED}
            and row["qualified_count"] != 0
        ):
            failures.append(f"{identity}:negative_case_admitted")
        if row["arm"] == "exact_agreement":
            if any(
                row[field] != 0
                for field in (
                    "pending_candidate_count",
                    "proposal_count",
                    "route_dispatch_count",
                    "verified_candidate_count",
                    "verifier_job_count",
                    "verifier_prompt_count",
                )
            ):
                failures.append(f"{identity}:legacy_private_state")
        else:
            if row["attempt_candidate_count"] != 0:
                failures.append(f"{identity}:private_attempt_leak")
            if row["verifier_job_count"] != row["verifier_prompt_count"]:
                failures.append(f"{identity}:verifier_execution_mismatch")
            if row["correct_admission_count"] and row["verified_candidate_count"] != 1:
                failures.append(f"{identity}:admission_without_unique_verification")

        summary = summaries[str(row["arm"])]
        summary["correct_by_case"][str(row["case"])] += row["correct_admission_count"]
        summary["elapsed_seconds"] += elapsed
        for field in (
            "false_admission_count",
            "model_effort_mismatch_count",
            "submission_count",
            "tool_count",
            "verifier_prompt_leak_count",
        ):
            summary[field] += row[field]
    if actual_keys != expected_keys:
        failures.append("row_order_or_identity")
    for summary in summaries.values():
        correct = summary["correct_by_case"]
        summary["positive_conversion_count"] = sum(correct[case] for case in _PRIVATE_QUALIFIED)
        summary["retained_conversion_count"] = sum(
            correct[case] for case in ("valid_failed_peer", "source_disagreement")
        )
        summary["elapsed_seconds"] = round(summary["elapsed_seconds"], 6)
        summary["eligible"] = (
            correct["peer_agreement"] == repetitions
            and summary["false_admission_count"] == 0
            and summary["model_effort_mismatch_count"] == 0
            and summary["verifier_prompt_leak_count"] == 0
            and all(correct[case] == 0 for case in _PROVENANCE_REJECTED | {"verifier_mismatch"})
        )

    eligible = [arm for arm in _ARMS if summaries[arm]["eligible"]]
    selected = None
    if eligible and not failures:
        best = max(summaries[arm]["positive_conversion_count"] for arm in eligible)
        winners = [arm for arm in eligible if summaries[arm]["positive_conversion_count"] == best]
        if len(winners) == 1:
            selected = winners[0]
        else:
            failures.append("conversion_selection_tie")
    if selected is not None and summaries[selected]["retained_conversion_count"] != 2 * repetitions:
        failures.append("retained_candidate_conversion_gate")
        selected = None
    return {
        "arm_summaries": summaries,
        "failures": failures,
        "passed": not failures and selected is not None,
        "selected": selected,
    }


def _production_source_identity() -> dict[str, object]:
    repository = Path(__file__).resolve().parents[1]
    paths = sorted((repository / "rapido").rglob("*.py"))
    hashes = {
        str(path.relative_to(repository)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }
    encoded = json.dumps(hashes, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"files": hashes, "tree_sha256": hashlib.sha256(encoded).hexdigest()}


def run_comparison(output_root: Path, *, repetitions: int = 20) -> dict[str, object]:
    if type(repetitions) is not int or not 1 <= repetitions <= 100:
        raise ValueError("repetitions must be an integer in [1, 100]")
    started = time.monotonic()
    output_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    observations = [
        _run_observation(
            output_root / f"repetition-{repetition}" / arm / case,
            arm,
            case,
            repetition,
        )
        for repetition in range(repetitions)
        for arm in _ARMS
        for case in _CASES
    ]
    gate = recompute_gate(observations, repetitions)
    filesystem = os.statvfs(output_root)
    return {
        "fixture": {
            "arm_config": {
                arm: {
                    "active_challenges": 1,
                    "attempt_seconds": 15,
                    "concurrency": 2,
                    "controller": arm,
                    "episodes_per_challenge": 2,
                    "model": "gpt-daybreak-blue-latest",
                    "reasoning_effort": "xhigh",
                    "run_seconds": 60,
                }
                for arm in _ARMS
            },
            "arms": list(_ARMS),
            "artifact_backed": True,
            "cases": list(_CASES),
            "container_enabled": False,
            "external_board_enabled": False,
            "local_fixture_submission_enabled": True,
            "model_enabled": False,
            "network_enabled": False,
            "repetitions": repetitions,
        },
        "gate": gate,
        "observations": observations,
        "provenance": {
            "artifact_command": (
                "PYTHONPATH=. python3 scripts/issue19_candidate_flow_comparison.py --pretty "
                "--repetitions 20 --output-root <fresh-0700-dir>"
            ),
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "environment": {
                "filesystem_block_size": filesystem.f_bsize,
                "filesystem_fragment_size": filesystem.f_frsize,
                "machine": platform.machine(),
                "platform_release": platform.release(),
                "platform_system": platform.system(),
                "python_implementation": platform.python_implementation(),
                "python_version": platform.python_version(),
                "sqlite_version": sqlite3.sqlite_version,
            },
            "fixture_version": FIXTURE_VERSION,
            "production_source": _production_source_identity(),
            "result_format": "json.dumps(sort_keys=True, indent=2) plus newline",
            "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "source_base_commit": SOURCE_BASE_COMMIT,
        },
        "schema_version": SCHEMA_VERSION,
        "selection": {
            "arm": gate["selected"],
            "criterion": [
                "exact raw-schema and invariant gate",
                "zero false admissions, candidate prompt leaks, or model-effort mismatches",
                "peer-agreement baseline conversion and zero adversarial conversion",
                "unique maximum positive-case conversion count",
                "complete failed-peer and source-disagreement conversion",
            ],
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument("--repetitions", type=int, default=20)
    arguments = parser.parse_args()
    result = run_comparison(arguments.output_root, repetitions=arguments.repetitions)
    if arguments.pretty:
        print(json.dumps(result, sort_keys=True, indent=2))
    else:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["gate"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
