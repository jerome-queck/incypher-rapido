#!/usr/bin/env python3
"""Run two real native Codex lanes against a hidden-answer offline fixture."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

from rapido.board import Challenge
from rapido.codex_app import CodexAppClient, TurnTimeoutError
from rapido.config import validate_codex_home
from rapido.solver import (
    OFFLINE_DEVELOPER_INSTRUCTIONS,
    SOLVER_OUTPUT_SCHEMA,
    SolverFinding,
    build_turn_prompt,
)


@dataclass(frozen=True)
class LaneEvidence:
    started: float
    finished: float
    finding: SolverFinding
    tool_calls: tuple[dict[str, object], ...]


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    result.add_argument("--codex-binary", required=True)
    result.add_argument("--codex-home", type=Path, required=True)
    result.add_argument("--work-root", type=Path, required=True)
    result.add_argument("--expected-sha256", required=True)
    result.add_argument("--model", default="gpt-6-astra")
    result.add_argument("--effort", default="xhigh")
    result.add_argument("--timeout", type=float, default=300)
    result.add_argument("--max-workspace-bytes", type=int, default=192 * 1024 * 1024)
    result.add_argument("--verify-timeout", action="store_true")
    return result


async def run(arguments: argparse.Namespace) -> dict[str, object]:
    validate_codex_home(arguments.codex_home)
    workspaces = [arguments.work_root / f"lane-{lane}" for lane in range(2)]
    for workspace in workspaces:
        if workspace.is_symlink() or not workspace.is_dir():
            raise ValueError("both acceptance lane workspaces must be real directories")
    challenge = Challenge(
        1,
        "Synthetic offline decoding",
        "misc",
        "standard",
        "An artifact contains an encoded candidate. Inspect and decode it independently.",
        0,
        (),
        False,
        0,
        0,
        None,
        None,
    )
    client = CodexAppClient(
        env={
            "CODEX_HOME": str(arguments.codex_home),
            "HOME": str(arguments.codex_home),
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "TERM": "dumb",
            "NO_COLOR": "1",
        },
        binary=arguments.codex_binary,
        model=arguments.model,
        reasoning_effort=arguments.effort,
        cwd=arguments.work_root,
        max_workspace_bytes=arguments.max_workspace_bytes,
    )

    async def lane(index: int, workspace: Path) -> LaneEvidence:
        started = time.monotonic()
        turn = await client.solve(
            workspace,
            build_turn_prompt(challenge, ["artifact.txt"], index),
            developer_instructions=OFFLINE_DEVELOPER_INSTRUCTIONS,
            model=arguments.model,
            reasoning_effort=arguments.effort,
            output_schema=SOLVER_OUTPUT_SCHEMA,
            timeout=arguments.timeout,
        )
        finished = time.monotonic()
        if turn.status != "completed":
            raise RuntimeError("native acceptance turn did not complete")
        finding = SolverFinding.from_message(turn.text)
        calls = tuple(dict(item) for item in turn.tool_calls)
        return LaneEvidence(started, finished, finding, calls)

    await asyncio.wait_for(client.start(), timeout=arguments.timeout)
    timeout_interrupt_sent = False
    timeout_process_fenced = False
    timeout_recovery_completed = False
    try:
        lanes = await asyncio.gather(
            *(lane(index, workspace) for index, workspace in enumerate(workspaces))
        )
        if arguments.verify_timeout:
            try:
                await client.solve(
                    workspaces[0],
                    build_turn_prompt(challenge, ["artifact.txt"], 99),
                    developer_instructions=OFFLINE_DEVELOPER_INSTRUCTIONS,
                    model=arguments.model,
                    reasoning_effort=arguments.effort,
                    output_schema=SOLVER_OUTPUT_SCHEMA,
                    timeout=0.001,
                )
            except TurnTimeoutError as exc:
                timeout_interrupt_sent = exc.interrupt_sent
                timeout_process_fenced = exc.process_fenced
            except TimeoutError:
                timeout_process_fenced = client.process is None
            if not (timeout_interrupt_sent or timeout_process_fenced):
                raise RuntimeError("native timeout did not confirm interruption or process fencing")
            recovery = await client.solve(
                workspaces[0],
                build_turn_prompt(challenge, ["artifact.txt"], 100),
                developer_instructions=OFFLINE_DEVELOPER_INSTRUCTIONS,
                model=arguments.model,
                reasoning_effort=arguments.effort,
                output_schema=SOLVER_OUTPUT_SCHEMA,
                timeout=arguments.timeout,
            )
            recovery_finding = SolverFinding.from_message(recovery.text)
            if recovery.status != "completed" or recovery_finding.candidate is None:
                raise RuntimeError("native client did not recover after the forced timeout")
            recovery_sha = hashlib.sha256(recovery_finding.candidate.encode()).hexdigest()
            if recovery_sha != arguments.expected_sha256 or not any(
                call.get("success") is True
                and call.get("source_bound") is True
                and recovery_sha in call.get("candidate_sha256s", ())
                for call in recovery.tool_calls
            ):
                raise RuntimeError("recovery turn lacked artifact-bound candidate evidence")
            timeout_recovery_completed = True
    finally:
        await client.close()
    candidates = {item.finding.candidate for item in lanes}
    if None in candidates or len(candidates) != 1:
        diagnostic = [
            {
                "status": item.finding.status,
                "calls": [
                    {
                        "name": str(call.get("name", "")),
                        "success": call.get("success"),
                        "source_bound": call.get("source_bound"),
                    }
                    for call in item.tool_calls
                ],
            }
            for item in lanes
        ]
        raise RuntimeError(
            "native lanes did not agree on one candidate: " + json.dumps(diagnostic, sort_keys=True)
        )
    candidate = next(iter(candidates))
    assert isinstance(candidate, str)
    fingerprint = hashlib.sha256(candidate.encode()).hexdigest()
    if fingerprint != arguments.expected_sha256:
        raise RuntimeError("native candidate fingerprint did not match the held-out expectation")
    if any(
        not any(
            call.get("success") is True
            and call.get("source_bound") is True
            and fingerprint in call.get("candidate_sha256s", ())
            for call in item.tool_calls
        )
        for item in lanes
    ):
        raise RuntimeError(
            "each native lane must derive the candidate through artifact-bound tools"
        )
    overlap = max(item.started for item in lanes) < min(item.finished for item in lanes)
    if not overlap:
        raise RuntimeError("native acceptance lanes did not overlap")
    return {
        "status": "passed",
        "model": arguments.model,
        "effort": arguments.effort,
        "lanes": len(lanes),
        "overlap": overlap,
        "timeout_interrupt_sent": timeout_interrupt_sent if arguments.verify_timeout else None,
        "timeout_process_fenced": timeout_process_fenced if arguments.verify_timeout else None,
        "timeout_recovery_completed": (
            timeout_recovery_completed if arguments.verify_timeout else None
        ),
        "candidate_sha256": fingerprint,
        "durations_seconds": [round(item.finished - item.started, 3) for item in lanes],
        "tool_calls": [
            [
                {
                    "name": str(call.get("name", "")),
                    "success": call.get("success"),
                    "source_bound": call.get("source_bound"),
                }
                for call in item.tool_calls
            ]
            for item in lanes
        ],
    }


def main() -> int:
    print(json.dumps(asyncio.run(run(parser().parse_args())), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
