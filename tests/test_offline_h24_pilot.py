from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from rapido.evidence import project_tool_observation

SPEC = importlib.util.spec_from_file_location(
    "offline_oracle_pilot_h24",
    Path(__file__).resolve().parents[1] / "scripts" / "offline_oracle_pilot.py",
)
assert SPEC is not None and SPEC.loader is not None
PILOT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PILOT
SPEC.loader.exec_module(PILOT)

SEED = b"h24-pilot-private-seed:" + b"s" * 48


def _private_file(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def _config(tmp_path: Path) -> PILOT.PilotConfig:
    auth = tmp_path / "auth"
    auth.mkdir(mode=0o700)
    _private_file(auth / "auth.json", b"{}")
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    key = _private_file(tmp_path / "oracle.key", SEED)
    return PILOT.PilotConfig("codex", auth, work, key, source_sha="c" * 40)


def _patch_identities(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        PILOT,
        "_source_identity",
        lambda supplied: {
            "observed": {"head_sha": supplied, "worktree": "clean"},
            "declared": {"sha": supplied},
            "declared_matches_head": True,
        },
    )
    monkeypatch.setattr(
        PILOT,
        "_image_identity",
        lambda supplied: {
            "observed": {"status": "unavailable"},
            "declared": {"status": "unavailable"},
            "declared_matches_observed": None,
        },
    )


def _unsolved_turn(thread_id: str) -> SimpleNamespace:
    return SimpleNamespace(
        status="completed",
        timed_out=False,
        failure_class=None,
        text=json.dumps(
            {
                "status": "unsolved",
                "candidate": None,
                "confidence": 0.0,
                "summary": "bounded fixture remained unresolved",
                "evidence": [],
                "next_steps": [],
            }
        ),
        tool_calls=[],
        current_turn_tool_calls=[],
        raw={"id": "turn", "status": "completed"},
        cumulative_native_usage=None,
        thread_id=thread_id,
    )


def _candidate_call(name: str, candidate: str) -> dict[str, object]:
    digest = hashlib.sha256(candidate.encode()).hexdigest()
    observation = project_tool_observation(
        name,
        success=True,
        source_bound=True,
        candidate_sha256s=(digest,),
        candidate_sensitive=True,
    )
    return {
        "name": name,
        "success": True,
        "source_bound": True,
        "candidate_sensitive": True,
        "candidate_sha256s": [digest],
        "supplied_candidate_sha256s": [],
        "host_observation": observation,
    }


def _candidate_turn(
    candidate: str,
    calls: list[dict[str, object]],
    *,
    current: list[dict[str, object]] | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        status="completed",
        timed_out=False,
        failure_class=None,
        text=json.dumps(
            {
                "status": "candidate",
                "candidate": candidate,
                "confidence": 1.0,
                "summary": "derived from local fixture bytes",
                "evidence": ["fixed local source observation"],
                "next_steps": [],
            }
        ),
        tool_calls=calls,
        current_turn_tool_calls=calls if current is None else current,
        raw={"usage": {"inputTokens": 10, "outputTokens": 2}},
        cumulative_native_usage=None,
        thread_id="same-thread",
    )


def test_h24_prepares_all_fixtures_before_client_or_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    _patch_identities(monkeypatch)
    prepared: list[str] = []
    preflighted: list[str] = []
    original_prepare = PILOT.prepare_h24_fixture
    original_preflight = PILOT.preflight_h24_fixture

    def record_prepare(seed: bytes, task_id: str):
        prepared.append(task_id)
        return original_prepare(seed, task_id)

    def fail_last_preflight(task: object, artifacts: object) -> None:
        preflighted.append(task.id)
        if len(preflighted) == 24:
            raise ValueError("synthetic final preflight")
        original_preflight(task, artifacts)

    factories = 0

    def factory(**_: object) -> object:
        nonlocal factories
        factories += 1
        raise AssertionError("client factory must not run")

    monkeypatch.setattr(PILOT, "prepare_h24_fixture", record_prepare)
    monkeypatch.setattr(PILOT, "preflight_h24_fixture", fail_last_preflight)
    with pytest.raises(ValueError, match="final preflight"):
        asyncio.run(PILOT.run_h24_pilot(config, client_factory=factory))

    assert len(prepared) == 24
    assert len(preflighted) == 24
    assert factories == 0
    assert list(config.work_root.iterdir()) == []


def test_supplied_source_sha_bypasses_git_but_unsupplied_checks_worktree(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def no_git(*_: object, **__: object) -> object:
        raise AssertionError("explicit packaged source identity must not invoke git")

    monkeypatch.setattr(PILOT.subprocess, "run", no_git)
    packaged = PILOT._source_identity("A" * 40)
    assert packaged == {
        "observed": {
            "head_sha": "a" * 40,
            "worktree": "packaged_source",
            "tracked_change_count": None,
            "untracked_file_count": None,
        },
        "declared": {"sha": "a" * 40},
        "declared_matches_head": True,
        "identity_basis": "supplied_full_sha",
    }
    with pytest.raises(ValueError, match="source SHA is invalid"):
        PILOT._source_identity("short")

    calls: list[tuple[str, ...]] = []

    def fake_git(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(tuple(command))
        stdout = "b" * 40 + "\n" if command[1] == "rev-parse" else " M README.md\n?? local.tmp\n"
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(PILOT.subprocess, "run", fake_git)
    inspected = PILOT._source_identity(None)
    assert calls == [
        ("git", "rev-parse", "--verify", "HEAD"),
        ("git", "status", "--porcelain=v1", "--untracked-files=all"),
    ]
    assert inspected["observed"] == {
        "head_sha": "b" * 40,
        "worktree": "dirty",
        "tracked_change_count": 1,
        "untracked_file_count": 1,
    }
    assert inspected["identity_basis"] == "git_worktree"


def test_h24_cli_selects_contextual_oracle_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    config = _config(tmp_path)
    seen: list[PILOT.PilotConfig] = []

    async def fake_h24(received: PILOT.PilotConfig) -> dict[str, object]:
        seen.append(received)
        return {"schema": "test-only"}

    monkeypatch.setattr(PILOT, "run_h24_pilot", fake_h24)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "offline_oracle_pilot.py",
            "--experiment",
            "h24",
            "--codex-binary",
            config.codex_binary,
            "--codex-home",
            str(config.codex_home),
            "--work-root",
            str(config.work_root),
            "--oracle-key-file",
            str(config.oracle_key_file),
        ],
    )
    assert PILOT.main() == 0
    assert len(seen) == 1
    assert seen[0].oracle_id == PILOT.H24_ORACLE_SCHEMA
    assert json.loads(capsys.readouterr().out) == {"schema": "test-only"}


def test_h24_prompts_instructions_sentinels_and_arm_copies_are_private(tmp_path: Path) -> None:
    fixtures = PILOT._prepare_h24_fixtures(SEED)
    assert len(fixtures) == 24
    assert {
        fixture.id: PILOT._H24_EASY_SENTINELS[fixture.id]
        for fixture in fixtures
        if fixture.family == "easy"
    } == {
        "h24-easy-01": "plain_text",
        "h24-easy-02": "structured_json",
        "h24-easy-03": "base64",
        "h24-easy-04": "hex",
        "h24-easy-05": "zip",
        "h24-easy-06": "binary_strings",
    }
    fixture = next(item for item in fixtures if item.id == "h24-hard-01")
    prompt = PILOT._h24_prompt(fixture)
    document = json.loads(prompt)
    assert document["prior_attempts"] == []
    assert document["same_run_memory"] == []
    assert document["workspace_artifacts"] == list(fixture.artifact_names)
    assert set(document["task"]) == {"id", "group", "scope", "instruction"}
    forbidden = {
        fixture.prepared.expected_answer,
        hashlib.sha256(fixture.prepared.expected_answer.encode()).hexdigest(),
        SEED.hex(),
        base64.b64encode(SEED).decode(),
    }
    assert all(value not in prompt for value in forbidden)
    instructions = " ".join(PILOT.H24_DEVELOPER_INSTRUCTIONS.lower().split())
    assert "board-issued target" not in instructions
    assert "ephemeral" not in instructions
    assert "official in-cypher" not in instructions
    assert "only relative files inside the assigned workspace" in instructions

    first = tmp_path / "one_shot" / fixture.id
    second = tmp_path / "evidence_repair" / fixture.id
    PILOT._stage_h24_fixture(fixture, first)
    PILOT._stage_h24_fixture(fixture, second)
    for artifact in fixture.prepared.artifacts:
        left = first.joinpath(*artifact.path.split("/"))
        right = second.joinpath(*artifact.path.split("/"))
        assert left.read_bytes() == right.read_bytes() == artifact.data
        assert left.stat().st_ino != right.stat().st_ino
    assert not any(path.name == "oracle.key" for path in first.rglob("*"))
    assert not any(path.name == "oracle.key" for path in second.rglob("*"))


def test_h24_descriptor_mismatch_fails_closed_with_48_rows_and_no_solve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    _patch_identities(monkeypatch)
    clients: list[object] = []

    class MissingEffortClient:
        def __init__(self, **_: object) -> None:
            self.solves = 0
            clients.append(self)

        async def start(self) -> None: ...

        async def validate_model(self, model: str, effort: str) -> SimpleNamespace:
            assert (model, effort) == (PILOT._VERIFIER_MODEL, PILOT._VERIFIER_EFFORT)
            return SimpleNamespace(
                name=model,
                reasoning_efforts=("high",),
                raw={"slug": model, "revision": "2026-09-19", "private": "must-not-copy"},
            )

        async def solve(self, *_: object, **__: object) -> object:
            self.solves += 1
            raise AssertionError("model mismatch must prevent solves")

        async def close(self) -> None: ...

    receipt = asyncio.run(PILOT.run_h24_pilot(config, client_factory=MissingEffortClient))
    assert len(clients) == 2
    assert sum(client.solves for client in clients) == 0
    assert len(receipt["results"]) == 48
    assert receipt["native_observability"]["attempt_count"] == 48
    assert receipt["native_observability"]["outcomes"]["provider_failure"] == 48
    assert receipt["protocol"]["fallback_allowed"] is False
    assert receipt["protocol"]["oracle_id"] == PILOT.H24_ORACLE_SCHEMA
    encoded = json.dumps(receipt)
    assert "must-not-copy" not in encoded
    for row in receipt["runtime"].values():
        assert row["descriptor"]["revision"] == "2026-09-19"
        assert row["descriptor"]["effort_supported"] is False


def test_h24_runner_serializes_startup_overlaps_pairs_and_retains_all_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    _patch_identities(monkeypatch)
    startup_active = startup_peak = turn_active = turn_peak = 0
    calls: list[dict[str, object]] = []

    class FakeClient:
        def __init__(self, **kwargs: object) -> None:
            self.arm = Path(str(kwargs["cwd"])).name

        async def start(self) -> None:
            nonlocal startup_active, startup_peak
            startup_active += 1
            startup_peak = max(startup_peak, startup_active)
            await asyncio.sleep(0)
            startup_active -= 1

        async def validate_model(self, model: str, effort: str) -> SimpleNamespace:
            return SimpleNamespace(
                name=model,
                reasoning_efforts=(effort,),
                raw={"slug": model, "modelVersion": "daybreak-test-v1"},
            )

        async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
            nonlocal turn_active, turn_peak
            turn_active += 1
            turn_peak = max(turn_peak, turn_active)
            artifact_inodes = tuple(
                sorted(path.stat().st_ino for path in workspace.rglob("*") if path.is_file())
            )
            calls.append(
                {
                    "arm": self.arm,
                    "workspace": workspace,
                    "prompt": prompt,
                    "instructions": kwargs["developer_instructions"],
                    "model": kwargs["model"],
                    "effort": kwargs["reasoning_effort"],
                    "timeout": kwargs["timeout"],
                    "inodes": artifact_inodes,
                }
            )
            await asyncio.sleep(0)
            result = _unsolved_turn(f"{self.arm}-{workspace.name}")
            callback = kwargs["continuation_callback"]
            assert callback(result, float(kwargs["timeout"]) - 0.001) is None
            turn_active -= 1
            return result

        async def close(self) -> None: ...

    receipt = asyncio.run(PILOT.run_h24_pilot(config, client_factory=FakeClient))
    assert startup_peak == 1
    assert turn_peak == 2
    assert len(calls) == 48
    assert len(receipt["results"]) == 48
    assert receipt["native_observability"]["attempt_count"] == 48
    assert receipt["native_observability"]["outcomes"]["inconclusive"] == 48
    assert {call["model"] for call in calls} == {PILOT._VERIFIER_MODEL}
    assert {call["effort"] for call in calls} == {PILOT._VERIFIER_EFFORT}
    assert {call["instructions"] for call in calls} == {PILOT.H24_DEVELOPER_INSTRUCTIONS}
    assert all(json.loads(str(call["prompt"]))["same_run_memory"] == [] for call in calls)
    by_task: dict[str, list[dict[str, object]]] = {}
    for call in calls:
        by_task.setdefault(Path(str(call["workspace"])).name, []).append(call)
    assert all(
        len(pair) == 2 and set(pair[0]["inodes"]).isdisjoint(set(pair[1]["inodes"]))
        for pair in by_task.values()
    )


def test_shared_deadline_repair_is_one_solve_same_thread_and_decreasing(tmp_path: Path) -> None:
    fixture = PILOT._prepare_h24_fixtures(SEED)[0]
    workspace = tmp_path / "workspace"
    PILOT._stage_h24_fixture(fixture, workspace)

    class Clock:
        value = 0.0

        def __call__(self) -> float:
            return self.value

    clock = Clock()

    class RepairClient:
        solves = 0
        follow_up = ""

        async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
            del workspace, prompt
            self.solves += 1
            candidate = fixture.prepared.expected_answer
            first_call = _candidate_call("run_shell", candidate)
            first = _candidate_turn(candidate, [first_call])
            clock.value = 20.0
            callback = kwargs["continuation_callback"]
            self.follow_up = callback(first, 290.0)
            assert isinstance(self.follow_up, str)
            clock.value = 40.0
            final_call = _candidate_call("read_text", candidate)
            return _candidate_turn(
                candidate,
                [first_call, final_call],
                current=[final_call],
            )

    client = RepairClient()
    deadline = PILOT.PairDeadline.admit(300, 0.0, 19_800.0)
    measurement = asyncio.run(
        PILOT._measure_verifier(
            client,
            fixture,
            PILOT.VERIFIER_ARMS[1],
            workspace,
            PILOT._h24_prompt(fixture),
            fixture.prepared.expected_answer,
            PILOT.MAX_WORKSPACE_BYTES,
            0.0,
            0.0,
            0.0,
            0.0,
            deadline=deadline,
            developer_instructions=PILOT.H24_DEVELOPER_INSTRUCTIONS,
            repair_prompt_builder=PILOT.build_h24_repair_prompt,
            clock=clock,
        )
    )
    assert client.solves == 1
    assert measurement.continuation_count == 1
    assert measurement.same_thread is True
    assert measurement.first.outcome == "rejected_correct"
    assert measurement.final.outcome == "verified_correct"
    follow_up = json.loads(client.follow_up)
    assert follow_up["remaining_milliseconds"] == 280_000
    assert fixture.prepared.expected_answer not in client.follow_up
    budget = measurement.native_receipt["budget"]
    assert budget == {
        "configured_milliseconds": 300_000,
        "granted_milliseconds": 300_000,
        "remaining_after_first_milliseconds": 280_000,
        "remaining_terminal_milliseconds": 260_000,
    }


def test_global_expiry_keeps_48_rows_without_late_solves(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    _patch_identities(monkeypatch)

    class Clock:
        value = 0.0

        def __call__(self) -> float:
            return self.value

    clock = Clock()
    solve_count = 0

    class ExpiringClient:
        def __init__(self, **kwargs: object) -> None:
            self.arm = Path(str(kwargs["cwd"])).name

        async def start(self) -> None: ...

        async def validate_model(self, model: str, effort: str) -> SimpleNamespace:
            return SimpleNamespace(name=model, reasoning_efforts=(effort,), raw={"slug": model})

        async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> object:
            del workspace, prompt
            nonlocal solve_count
            solve_count += 1
            await asyncio.sleep(0)
            clock.value = PILOT.H24_GLOBAL_SECONDS + 1
            return _unsolved_turn(self.arm)

        async def close(self) -> None: ...

    receipt = asyncio.run(PILOT.run_h24_pilot(config, client_factory=ExpiringClient, clock=clock))
    assert solve_count == 2
    assert len(receipt["results"]) == 48
    outcomes = receipt["native_observability"]["outcomes"]
    assert outcomes["inconclusive"] == 0
    assert outcomes["timeout"] == 48
    assert all(
        row["native_observability"]["budget"]["granted_milliseconds"] == 0
        for row in receipt["results"][2:]
    )


def test_easy_gate_keeps_correctness_and_qualification_independent() -> None:
    measurements = []
    for task_id in PILOT._H24_EASY_SENTINELS:
        for arm in PILOT.VERIFIER_ARMS:
            final = PILOT.VerifierTurnEvaluation("verified_correct", None)
            measurements.append(
                PILOT.VerifierMeasurement(
                    task_id=task_id,
                    family="easy",
                    arm=arm,
                    first=final,
                    final=final,
                    fixture_elapsed_seconds=0.0,
                    first_turn_seconds=10.0 if arm.id == "one_shot" else 11.0,
                    repair_turn_seconds=0.0,
                    repair_attempted=False,
                    continuation_count=0,
                    same_thread=True,
                    continuation_prompt_candidate_free=True,
                    first_tool_calls=1,
                    final_tool_calls=1,
                    cumulative_tool_calls=1,
                    tool_errors={"total": 0},
                    first_native_usage={},
                    final_native_usage={},
                    failure_class=None,
                    native_receipt={},
                )
            )
    rejected = replace(
        measurements[-1],
        final=PILOT.VerifierTurnEvaluation("rejected_correct", "candidate_unobserved"),
    )
    summary = PILOT._h24_summary(measurements)
    assert summary["easy_sentinels"]["passed"] is True
    assert summary["arms"]["evidence_repair"]["oracle_correct"] == 6
    assert summary["arms"]["evidence_repair"]["qualified_correct"] == 6
    regressed = PILOT._h24_summary([*measurements[:-1], rejected])
    assert regressed["arms"]["evidence_repair"]["oracle_correct"] == 6
    assert regressed["arms"]["evidence_repair"]["qualified_correct"] == 5
    assert regressed["easy_sentinels"]["passed"] is False
