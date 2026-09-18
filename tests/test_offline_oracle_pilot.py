from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from rapido.codex_app import ModelValidationError
from rapido.evidence import project_tool_observation
from rapido.tools import ToolError, ToolRegistry

SPEC = importlib.util.spec_from_file_location(
    "offline_oracle_pilot",
    Path(__file__).resolve().parents[1] / "scripts" / "offline_oracle_pilot.py",
)
assert SPEC is not None and SPEC.loader is not None
PILOT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PILOT
SPEC.loader.exec_module(PILOT)


def _private_file(path: Path, payload: bytes) -> Path:
    path.write_bytes(payload)
    path.chmod(0o600)
    return path


def _roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    codex_home = tmp_path / "auth"
    codex_home.mkdir(mode=0o700)
    _private_file(codex_home / "auth.json", b"{}")
    work_root = tmp_path / "work"
    work_root.mkdir(mode=0o700)
    key_file = _private_file(tmp_path / "oracle.key", b"private-test-key:" + b"k" * 48)
    return codex_home, work_root, key_file


def _patch_source_observation(monkeypatch: pytest.MonkeyPatch, *, clean: bool = False) -> None:
    def completed(command: list[str], **_: object) -> SimpleNamespace:
        if command[1:3] == ["rev-parse", "--verify"]:
            return SimpleNamespace(stdout="c" * 40 + "\n")
        assert command[1:3] == ["status", "--porcelain=v1"]
        return SimpleNamespace(stdout="" if clean else " M rapido/example.py\n?? scripts/new.py\n")

    monkeypatch.setattr(PILOT.subprocess, "run", completed)


def _candidate_call(
    name: str,
    candidate: str,
    *,
    supplied: bool = False,
) -> dict[str, object]:
    digest = hashlib.sha256(candidate.encode()).hexdigest()
    observation = project_tool_observation(
        name,
        success=True,
        source_bound=True,
        candidate_sha256s=(digest,),
        supplied_candidate_sha256s=(digest,) if supplied else (),
        candidate_sensitive=True,
    )
    return {
        "name": name,
        "success": True,
        "source_bound": True,
        "candidate_sensitive": True,
        "candidate_sha256s": [digest],
        "supplied_candidate_sha256s": [digest] if supplied else [],
        "host_observation": observation,
    }


def _verifier_turn(
    candidate: str,
    calls: list[dict[str, object]],
    *,
    current_calls: list[dict[str, object]] | None = None,
    thread_id: str = "thread-verifier",
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
                "summary": f"derived {candidate} from the fixture",
                "evidence": [f"fixture observation contained {candidate}"],
                "next_steps": [],
            }
        ),
        tool_calls=calls,
        current_turn_tool_calls=calls if current_calls is None else current_calls,
        raw={"usage": {"inputTokens": 10, "outputTokens": 2}},
        thread_id=thread_id,
    )


def _passing_gate_inputs() -> tuple[
    list[object], dict[str, object], dict[str, object], dict[str, object]
]:
    measurements: list[object] = []
    for fixture in PILOT.fixture_catalogue():
        for arm in PILOT.VERIFIER_ARMS:
            verified = PILOT.VerifierTurnEvaluation("verified_correct", None)
            first = (
                PILOT.VerifierTurnEvaluation(
                    "rejected_correct", "verifier_requires_fixed_observation"
                )
                if arm.continuation
                else verified
            )
            measurements.append(
                PILOT.VerifierMeasurement(
                    task_id=fixture.id,
                    family=fixture.family,
                    arm=arm,
                    first=first,
                    final=verified,
                    fixture_elapsed_seconds=0.001,
                    first_turn_seconds=0.01,
                    repair_turn_seconds=0.01 if arm.continuation else 0.0,
                    repair_attempted=arm.continuation,
                    continuation_count=1 if arm.continuation else 0,
                    same_thread=True,
                    continuation_prompt_candidate_free=True,
                    first_tool_calls=1,
                    final_tool_calls=1,
                    cumulative_tool_calls=2 if arm.continuation else 1,
                    tool_errors={
                        "total": 0,
                        "untyped": 0,
                        "by_stage": {},
                        "by_constraint": {},
                    },
                    first_native_usage={"status": "observed", "input_tokens": 1},
                    final_native_usage={"status": "observed", "input_tokens": 1},
                    failure_class=None,
                )
            )
    runtime = {
        arm.id: {
            "model": "gpt-daybreak-blue-latest",
            "effort": "xhigh",
            "status": "completed",
            "spans": {"cleanup": {"status": "completed"}},
        }
        for arm in PILOT.VERIFIER_ARMS
    }
    source = {
        "observed": {
            "head_sha": "c" * 40,
            "worktree": "clean",
            "tracked_change_count": 0,
            "untracked_file_count": 0,
        },
        "declared": {"sha": "c" * 40},
        "declared_matches_head": True,
    }
    image = {
        "observed": {"status": "unavailable"},
        "declared": {"status": "unavailable"},
        "declared_matches_observed": None,
    }
    return measurements, runtime, source, image


def test_catalogue_has_two_private_synthetic_fixtures_per_family() -> None:
    fixtures = PILOT.fixture_catalogue()
    families = {fixture.family for fixture in fixtures}

    assert len(fixtures) == 12
    assert {family: sum(item.family == family for item in fixtures) for family in families} == {
        family: 2 for family in families
    }
    key = b"k" * 32
    answers = [PILOT.oracle_answer(key, fixture.id) for fixture in fixtures]
    assert len(set(answers)) == 12
    assert all(answer not in Path(__file__).read_text(encoding="utf-8") for answer in answers)


def test_verifier_prompt_uses_production_route_with_empty_candidate_context() -> None:
    document = json.loads(PILOT._verifier_prompt(PILOT.fixture_catalogue()[0]))

    assert document["agent_role"] == "verifier"
    assert document["control_route"]["role"] == "verifier"
    assert document["control_route"]["tactic"] == "independent_source_reobservation"
    assert document["control_route"]["context_profile"] == "fresh_source_only_no_candidate_carry"
    assert document["control_route"]["verification_recipe"] == "fresh_source_reobservation_v1"
    assert document["control_route"]["model"] == "gpt-daybreak-blue-latest"
    assert document["control_route"]["effort"] == "xhigh"
    assert document["prior_attempts"] == []
    assert document["prior_observations"] is None
    assert document["same_run_memory"] == []
    assert "successful non-run_shell fixed source or target tool observation" in document["task"]


def test_verifier_evaluation_uses_current_validation_and_durable_whole_attempt_taint() -> None:
    fixture = PILOT.fixture_catalogue()[0]
    challenge = PILOT._challenge(fixture)
    expected = PILOT.oracle_answer(b"e" * 32, fixture.id)
    fixed = _candidate_call("read_text", expected)
    shell = _candidate_call("run_shell", expected)
    supplied = _candidate_call("inspect_file", expected, supplied=True)

    assert (
        PILOT._evaluate_verifier_turn(
            _verifier_turn(expected, []), expected, challenge
        ).rejection_reason
        == "candidate_unobserved"
    )
    assert (
        PILOT._evaluate_verifier_turn(
            _verifier_turn(expected, [shell]), expected, challenge
        ).rejection_reason
        == "verifier_requires_fixed_observation"
    )
    assert (
        PILOT._evaluate_verifier_turn(
            _verifier_turn(expected, [supplied, fixed], current_calls=[fixed]),
            expected,
            challenge,
        ).rejection_reason
        == "candidate_supplied"
    )
    verified = PILOT._evaluate_verifier_turn(_verifier_turn(expected, [fixed]), expected, challenge)
    assert verified.outcome == "verified_correct"
    assert verified.rejection_reason is None

    malformed = dict(fixed)
    malformed.pop("host_observation")
    assert (
        PILOT._evaluate_verifier_turn(
            _verifier_turn(expected, [malformed]), expected, challenge
        ).rejection_reason
        == "candidate_evidence_incomplete"
    )


def test_verifier_repair_prompt_is_candidate_free_and_rejects_tainted_routes() -> None:
    candidate = PILOT.oracle_answer(b"p" * 32, "task-01")
    prompt = PILOT.build_verifier_repair_prompt("verifier_requires_fixed_observation", 91.234)
    document = json.loads(prompt)

    assert document["label"] == "TRUSTED_VERIFIER_EVIDENCE_REPAIR"
    assert document["continuation_round"] == 1
    assert document["remaining_milliseconds"] == 91_234
    assert all(form not in prompt for form in PILOT._candidate_forms(candidate))
    for rejection in ("candidate_supplied", "candidate_evidence_incomplete"):
        with pytest.raises(ValueError, match="not repairable"):
            PILOT.build_verifier_repair_prompt(rejection, 10)


def test_score_requires_source_proof_for_correct_and_wrong_answers() -> None:
    expected = PILOT.oracle_answer(b"e" * 32, "task-01")
    wrong = PILOT.oracle_answer(b"w" * 32, "task-01")

    assert PILOT.score_answer(expected=expected, observed=expected, source_proved=True) == "correct"
    assert PILOT.score_answer(expected=expected, observed=wrong, source_proved=True) == "wrong"
    assert (
        PILOT.score_answer(
            expected=expected,
            observed=expected,
            source_proved=False,
            account_history="already_solved",
        )
        == "unverifiable"
    )
    assert (
        PILOT.score_answer(
            expected=expected,
            observed=wrong,
            source_proved=False,
            account_history="already_solved",
        )
        == "unverifiable"
    )


def test_oracle_key_must_stay_private_and_outside_lane_workspace(tmp_path: Path) -> None:
    _, work_root, key_file = _roots(tmp_path)
    lane = work_root / "lane"
    lane.mkdir(mode=0o700)
    registry = ToolRegistry(lane)

    with pytest.raises(ToolError):
        registry.dispatch("read_text", {"path": str(key_file)})
    key_file.chmod(0o644)
    with pytest.raises(ValueError, match="must not grant"):
        PILOT._private_regular_file(key_file, (work_root,))


class _ConcurrencyProbe:
    def __init__(self) -> None:
        self.active = 0
        self.peak = 0

    async def enter(self) -> None:
        self.active += 1
        self.peak = max(self.peak, self.active)
        await asyncio.sleep(0.001)

    def leave(self) -> None:
        self.active -= 1


class _FakeClient:
    def __init__(
        self,
        key: bytes,
        probe: _ConcurrencyProbe,
        *,
        fail_solves: bool = False,
        mismatch: bool = False,
        fail_close: bool = False,
        **kwargs: object,
    ) -> None:
        self.key = key
        self.probe = probe
        arm_id = Path(str(kwargs["cwd"])).name
        self.model = next(arm.model for arm in PILOT.ARMS if arm.id == arm_id)
        self.init = kwargs
        self.fail_solves = fail_solves
        self.mismatch = mismatch
        self.fail_close = fail_close
        self.validations: list[tuple[str, str]] = []
        self.solves: list[dict[str, object]] = []
        self.started = False
        self.closed = False

    async def start(self) -> None:
        self.started = True

    async def validate_model(self, model: str, effort: str) -> SimpleNamespace:
        self.validations.append((model, effort))
        if self.mismatch:
            raise ModelValidationError("synthetic exact-model mismatch")
        return SimpleNamespace(name=model, reasoning_efforts=(effort,))

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> SimpleNamespace:
        await self.probe.enter()
        try:
            if self.fail_solves:
                raise RuntimeError("synthetic arm process failure")
            document = json.loads(prompt)
            task_id = f"task-{int(document['challenge']['id']):02d}"
            answer = PILOT.oracle_answer(self.key, task_id)
            digest = hashlib.sha256(answer.encode()).hexdigest()
            registry = kwargs["tool_registry"]
            assert isinstance(registry, ToolRegistry)
            assert registry.workspace.root == workspace.resolve()
            self.solves.append(
                {
                    "task_id": task_id,
                    "prompt": prompt,
                    "workspace": workspace,
                    **kwargs,
                }
            )
            failed = {
                "name": "read_text",
                "success": False,
                "source_bound": True,
                "host_observation": SimpleNamespace(
                    facts={
                        "failure_stage": "arguments",
                        "constraint": "type",
                        "raw": "must never enter the receipt",
                    }
                ),
            }
            proved = {
                "name": "read_text",
                "success": True,
                "source_bound": True,
                "candidate_sha256s": [digest],
                "supplied_candidate_sha256s": [],
            }
            return SimpleNamespace(
                status="completed",
                timed_out=False,
                failure_class=None,
                text=json.dumps(
                    {
                        "status": "candidate",
                        "candidate": answer,
                        "confidence": 1.0,
                        "summary": f"derived {answer}",
                        "evidence": [f"source contained {answer}"],
                        "next_steps": [],
                    }
                ),
                tool_calls=[failed, proved],
                raw={"usage": {"inputTokens": 10, "outputTokens": 2}},
            )
        finally:
            self.probe.leave()

    async def close(self) -> None:
        self.closed = True
        if self.fail_close:
            raise RuntimeError("synthetic close failure")


class _VerifierFakeClient:
    def __init__(self, key: bytes, **kwargs: object) -> None:
        self.key = key
        self.arm = Path(str(kwargs["cwd"])).name
        self.started = False
        self.closed = False
        self.validations: list[tuple[str, str]] = []
        self.prompts: list[str] = []
        self.follow_ups: list[str] = []

    async def start(self) -> None:
        self.started = True

    async def validate_model(self, model: str, effort: str) -> SimpleNamespace:
        self.validations.append((model, effort))
        return SimpleNamespace(name=model, reasoning_efforts=(effort,))

    async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> SimpleNamespace:
        self.prompts.append(prompt)
        document = json.loads(prompt)
        task_id = f"task-{int(document['challenge']['id']):02d}"
        candidate = PILOT.oracle_answer(self.key, task_id)
        thread_id = f"{self.arm}-{task_id}"
        initial_call = _candidate_call(
            "read_text" if self.arm == "one_shot" else "run_shell",
            candidate,
        )
        initial = _verifier_turn(candidate, [initial_call], thread_id=thread_id)
        callback = kwargs.get("continuation_callback")
        if callback is None:
            return initial
        follow_up = callback(initial, 240.0)
        if follow_up is None:
            return initial
        assert isinstance(follow_up, str)
        self.follow_ups.append(follow_up)
        fixed = _candidate_call("read_text", candidate)
        final = _verifier_turn(
            candidate,
            [initial_call, fixed],
            current_calls=[fixed],
            thread_id=thread_id,
        )
        assert callback(final, 180.0) is None
        return final

    async def close(self) -> None:
        self.closed = True


def _factory(
    key: bytes,
    probe: _ConcurrencyProbe,
    clients: list[_FakeClient],
    *,
    failed_model: str | None = None,
    mismatched_model: str | None = None,
    close_failed_model: str | None = None,
):
    def make(**kwargs: object) -> _FakeClient:
        arm_id = Path(str(kwargs["cwd"])).name
        model = next(arm.model for arm in PILOT.ARMS if arm.id == arm_id)
        client = _FakeClient(
            key,
            probe,
            fail_solves=model == failed_model,
            mismatch=model == mismatched_model,
            fail_close=model == close_failed_model,
            **kwargs,
        )
        clients.append(client)
        return client

    return make


def test_fake_pilot_uses_isolated_concurrent_processes_and_sanitizes_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_source_observation(monkeypatch)
    monkeypatch.setenv("RAPIDO_IMAGE_ID", "sha256:" + "d" * 64)
    codex_home, work_root, key_file = _roots(tmp_path)
    key = key_file.read_bytes()
    probe = _ConcurrencyProbe()
    clients: list[_FakeClient] = []
    config = PILOT.PilotConfig(
        codex_binary="codex",
        codex_home=codex_home,
        work_root=work_root,
        oracle_key_file=key_file,
        source_sha="a" * 40,
        image_id="sha256:" + "b" * 64,
    )

    receipt = asyncio.run(PILOT.run_pilot(config, client_factory=_factory(key, probe, clients)))

    assert len(clients) == 2
    assert len({id(client) for client in clients}) == 2
    assert all(client.started and client.closed for client in clients)
    assert {client.model for client in clients} == {arm.model for arm in PILOT.ARMS}
    assert probe.peak == 2
    assert all(client.validations == [(client.model, "xhigh")] for client in clients)

    solves = [solve for client in clients for solve in client.solves]
    assert len(solves) == 24
    for fixture in PILOT.fixture_catalogue():
        pair = [solve for solve in solves if solve["task_id"] == fixture.id]
        assert len(pair) == 2
        assert pair[0]["prompt"] == pair[1]["prompt"]
        assert json.loads(pair[0]["prompt"])["agent_role"] == "specialist"
        assert {solve["model"] for solve in pair} == {arm.model for arm in PILOT.ARMS}
        assert {solve["timeout"] for solve in pair} == {300.0}
        assert all("continuation_callback" not in solve for solve in pair)

    assert receipt["source"] == {
        "observed": {
            "head_sha": "c" * 40,
            "worktree": "dirty",
            "tracked_change_count": 1,
            "untracked_file_count": 1,
        },
        "declared": {"sha": "a" * 40},
        "declared_matches_head": False,
    }
    assert receipt["image"] == {
        "observed": {"id": "sha256:" + "d" * 64},
        "declared": {"id": "sha256:" + "b" * 64},
        "declared_matches_observed": False,
    }
    assert receipt["protocol"]["fixture_count"] == 12
    assert receipt["protocol"]["fresh_thread_per_task"] is True
    assert receipt["protocol"]["fallback_allowed"] is False
    assert len(receipt["results"]) == 24
    assert {row["outcome"] for row in receipt["results"]} == {"correct"}
    assert all(row["native_usage"]["status"] == "observed" for row in receipt["results"])
    assert all(
        set(row["spans"]) == {"fixture_setup_seconds", "turn_seconds"} for row in receipt["results"]
    )
    for arm in PILOT.ARMS:
        runtime = receipt["runtime"][arm.id]
        assert runtime["status"] == "completed"
        assert {span["status"] for span in runtime["spans"].values()} == {"completed"}
        summary = receipt["summary"][arm.id]
        assert summary["outcomes"]["correct"] == 12
        assert summary["tool_errors_untyped"] == 0
        assert summary["tool_errors_by_constraint"] == {"type": 12}
        assert summary["native_usage"] == {
            "status": "observed",
            "turns_observed": 12,
            "turns_unavailable": 0,
            "totals": {"input_tokens": 120, "output_tokens": 24},
        }

    encoded = json.dumps(receipt, sort_keys=True)
    assert "must never enter the receipt" not in encoded
    for fixture in PILOT.fixture_catalogue():
        answer = PILOT.oracle_answer(key, fixture.id)
        forbidden = {
            answer,
            hashlib.sha256(answer.encode()).hexdigest(),
            base64.b64encode(answer.encode()).decode(),
            answer.encode().hex(),
        }
        assert all(value not in encoded for value in forbidden)
    assert list(work_root.iterdir()) == []


def test_arm_failure_and_cleanup_failure_do_not_corrupt_peer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_source_observation(monkeypatch)
    codex_home, work_root, key_file = _roots(tmp_path)
    probe = _ConcurrencyProbe()
    clients: list[_FakeClient] = []
    failed = PILOT.ARMS[0].model
    config = PILOT.PilotConfig("codex", codex_home, work_root, key_file)

    receipt = asyncio.run(
        PILOT.run_pilot(
            config,
            client_factory=_factory(
                key_file.read_bytes(),
                probe,
                clients,
                failed_model=failed,
                close_failed_model=failed,
            ),
        )
    )

    assert len(clients) == 2 and all(client.closed for client in clients)
    assert receipt["summary"][PILOT.ARMS[0].id]["outcomes"]["provider_failure"] == 12
    assert receipt["summary"][PILOT.ARMS[1].id]["outcomes"]["correct"] == 12
    assert receipt["runtime"][PILOT.ARMS[0].id]["spans"]["cleanup"]["status"] == "failed"
    assert receipt["runtime"][PILOT.ARMS[1].id]["status"] == "completed"
    assert list(work_root.iterdir()) == []


def test_model_mismatch_fails_only_affected_arm_without_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_source_observation(monkeypatch)
    codex_home, work_root, key_file = _roots(tmp_path)
    probe = _ConcurrencyProbe()
    clients: list[_FakeClient] = []
    mismatched = PILOT.ARMS[0]
    config = PILOT.PilotConfig("codex", codex_home, work_root, key_file)

    receipt = asyncio.run(
        PILOT.run_pilot(
            config,
            client_factory=_factory(
                key_file.read_bytes(), probe, clients, mismatched_model=mismatched.model
            ),
        )
    )

    failed = receipt["runtime"][mismatched.id]
    assert failed["status"] == "failed"
    assert failed["failure_class"] == "model_validation"
    assert failed["spans"]["model_validation"]["status"] == "failed"
    assert receipt["summary"][mismatched.id]["outcomes"]["provider_failure"] == 12
    assert receipt["summary"][PILOT.ARMS[1].id]["outcomes"]["correct"] == 12
    assert next(client for client in clients if client.model == mismatched.model).solves == []
    assert all(client.closed for client in clients)


def test_fake_verifier_repair_pilot_reuses_thread_and_emits_candidate_free_metrics(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_source_observation(monkeypatch, clean=True)
    codex_home, work_root, key_file = _roots(tmp_path)
    key = key_file.read_bytes()
    clients: list[_VerifierFakeClient] = []

    def factory(**kwargs: object) -> _VerifierFakeClient:
        client = _VerifierFakeClient(key, **kwargs)
        clients.append(client)
        return client

    config = PILOT.PilotConfig("codex", codex_home, work_root, key_file, source_sha="c" * 40)
    receipt = asyncio.run(PILOT.run_verifier_repair_pilot(config, client_factory=factory))

    assert receipt["schema"] == "rapido-offline-verifier-repair-v1"
    assert receipt["protocol"]["experiment"] == "verifier-repair"
    assert receipt["protocol"]["whole_attempt_taint"] is True
    assert receipt["protocol"]["fixed_non_run_shell_observation_required"] is True
    assert receipt["protocol"]["prompt_parity"] == {
        "offline_developer_authorization_preamble_differs_from_production": True,
        "common_developer_rules_match_production": True,
        "verifier_task_and_route_match_production": True,
    }
    assert receipt["protocol"]["source_identity_required"] is True
    assert receipt["protocol"]["image_identity_required"] is False
    assert receipt["gate"]["status"] == "passed"
    assert receipt["gate"]["checks"]["source_identity"]["passed"] is True
    assert receipt["gate"]["checks"]["image_identity"]["status"] == "not_required"
    assert len(receipt["results"]) == 24
    repair_rows = [row for row in receipt["results"] if row["arm"] == "evidence_repair"]
    assert len(repair_rows) == 12
    assert all(row["first"]["outcome"] == "rejected_correct" for row in repair_rows)
    assert all(
        row["first"]["rejection_reason"] == "verifier_requires_fixed_observation"
        for row in repair_rows
    )
    assert all(row["final"]["outcome"] == "verified_correct" for row in repair_rows)
    assert all(row["repair_attempted"] and row["continuation_count"] == 1 for row in repair_rows)
    assert all(row["same_thread"] for row in repair_rows)
    assert all(row["continuation_prompt_candidate_free"] for row in repair_rows)
    assert len(clients) == 2
    assert all(client.started and client.closed for client in clients)
    assert all(client.validations == [("gpt-daybreak-blue-latest", "xhigh")] for client in clients)
    repair_client = next(client for client in clients if client.arm == "evidence_repair")
    one_shot_client = next(client for client in clients if client.arm == "one_shot")
    assert one_shot_client.prompts == repair_client.prompts
    assert len(repair_client.follow_ups) == 12

    encoded = json.dumps(receipt, sort_keys=True)
    for fixture in PILOT.fixture_catalogue():
        candidate = PILOT.oracle_answer(key, fixture.id)
        assert all(form not in encoded for form in PILOT._candidate_forms(candidate))
        assert all(
            form not in follow_up
            for form in PILOT._candidate_forms(candidate)
            for follow_up in repair_client.follow_ups
        )
    assert list(work_root.iterdir()) == []


def test_verifier_repair_does_not_continue_supplied_candidate(tmp_path: Path) -> None:
    fixture = PILOT.fixture_catalogue()[0]
    candidate = PILOT.oracle_answer(b"s" * 32, fixture.id)

    class SuppliedClient:
        async def solve(self, workspace: Path, prompt: str, **kwargs: object) -> SimpleNamespace:
            del workspace, prompt
            turn = _verifier_turn(
                candidate, [_candidate_call("inspect_file", candidate, supplied=True)]
            )
            callback = kwargs["continuation_callback"]
            assert callback(turn, 200.0) is None
            return turn

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    measurement = asyncio.run(
        PILOT._measure_verifier(
            SuppliedClient(),
            fixture,
            next(arm for arm in PILOT.VERIFIER_ARMS if arm.id == "evidence_repair"),
            workspace,
            PILOT._verifier_prompt(fixture),
            candidate,
            PILOT.MAX_WORKSPACE_BYTES,
            0.0,
        )
    )

    assert measurement.first.rejection_reason == "candidate_supplied"
    assert measurement.final.rejection_reason == "candidate_supplied"
    assert measurement.repair_attempted is False
    assert measurement.continuation_count == 0


def test_parser_preserves_model_comparison_as_default() -> None:
    arguments = PILOT.parser().parse_args(
        [
            "--codex-binary",
            "codex",
            "--codex-home",
            "/tmp/auth",
            "--work-root",
            "/tmp/work",
            "--oracle-key-file",
            "/tmp/key",
        ]
    )
    assert arguments.experiment == "model-comparison"
    assert (
        PILOT.parser()
        .parse_args(
            [
                "--experiment",
                "verifier-repair",
                "--codex-binary",
                "codex",
                "--codex-home",
                "/tmp/auth",
                "--work-root",
                "/tmp/work",
                "--oracle-key-file",
                "/tmp/key",
            ]
        )
        .experiment
        == "verifier-repair"
    )


def test_verifier_gate_rejects_duplicate_and_missing_fixture_arm_identity() -> None:
    measurements, runtime, source, image = _passing_gate_inputs()
    corrupted = [*measurements[:-1], measurements[0]]

    gate = PILOT._verifier_gate(
        corrupted,
        runtime,
        source,
        image,
        image_required=False,
    )

    assert gate["status"] == "failed"
    identity = gate["checks"]["exact_fixture_arm_identities"]
    assert identity["passed"] is False
    assert len(identity["missing"]) == 1
    assert len(identity["duplicates"]) == 1


def test_verifier_gate_underpowered_is_inconclusive_only_when_otherwise_clean() -> None:
    measurements, runtime, source, image = _passing_gate_inputs()
    underpowered = [
        replace(
            row,
            first=PILOT.VerifierTurnEvaluation("verified_correct", None),
            repair_turn_seconds=0.0,
            repair_attempted=False,
            continuation_count=0,
        )
        if row.arm.id == "evidence_repair"
        else row
        for row in measurements
    ]
    clean_gate = PILOT._verifier_gate(
        underpowered,
        runtime,
        source,
        image,
        image_required=False,
    )
    assert clean_gate["status"] == "inconclusive"

    unsafe = list(underpowered)
    unsafe[0] = replace(
        unsafe[0],
        first=PILOT.VerifierTurnEvaluation("verified_wrong", None),
        final=PILOT.VerifierTurnEvaluation("verified_wrong", None),
    )
    unsafe_gate = PILOT._verifier_gate(
        unsafe,
        runtime,
        source,
        image,
        image_required=False,
    )
    assert unsafe_gate["status"] == "failed"
    assert unsafe_gate["checks"]["verified_wrong_task_arm_rows"]["actual"] == 1

    timed_out = list(underpowered)
    timed_out[-1] = replace(
        timed_out[-1],
        final=PILOT.VerifierTurnEvaluation("timeout", None),
        failure_class="timeout",
    )
    timeout_gate = PILOT._verifier_gate(
        timed_out,
        runtime,
        source,
        image,
        image_required=False,
    )
    assert timeout_gate["status"] == "failed"
    assert timeout_gate["checks"]["provider_failures_or_timeouts"]["passed"] is False

    unsafe_continuation = list(underpowered)
    repair_index = next(
        index for index, row in enumerate(unsafe_continuation) if row.arm.id == "evidence_repair"
    )
    unsafe_continuation[repair_index] = replace(
        unsafe_continuation[repair_index],
        first=PILOT.VerifierTurnEvaluation("rejected_correct", "candidate_supplied"),
        repair_attempted=True,
        continuation_count=1,
        repair_turn_seconds=0.01,
    )
    continuation_gate = PILOT._verifier_gate(
        unsafe_continuation,
        runtime,
        source,
        image,
        image_required=False,
    )
    assert continuation_gate["status"] == "failed"
    assert continuation_gate["checks"]["unsafe_continuations"]["actual"] == 1


def test_verifier_gate_counts_only_attempted_repairs_as_conversions() -> None:
    measurements, runtime, source, image = _passing_gate_inputs()
    unattempted = list(measurements)
    repair_index = next(
        index for index, row in enumerate(unattempted) if row.arm.id == "evidence_repair"
    )
    unattempted[repair_index] = replace(
        unattempted[repair_index],
        repair_attempted=False,
        continuation_count=0,
        repair_turn_seconds=0.0,
    )

    gate = PILOT._verifier_gate(
        unattempted,
        runtime,
        source,
        image,
        image_required=False,
    )

    assert gate["checks"]["repair_conversion"]["eligible"] == 12
    assert gate["checks"]["repair_conversion"]["actual"] == 11


def test_verifier_gate_requires_clean_declared_source_and_required_image_match() -> None:
    measurements, runtime, source, image = _passing_gate_inputs()
    dirty_source = {
        **source,
        "observed": {
            **source["observed"],
            "worktree": "dirty",
            "tracked_change_count": 1,
        },
    }
    source_gate = PILOT._verifier_gate(
        measurements,
        runtime,
        dirty_source,
        image,
        image_required=False,
    )
    assert source_gate["status"] == "failed"
    assert source_gate["checks"]["source_identity"]["passed"] is False

    source_mismatch = {**source, "declared_matches_head": False}
    mismatch_gate = PILOT._verifier_gate(
        measurements,
        runtime,
        source_mismatch,
        image,
        image_required=False,
    )
    assert mismatch_gate["status"] == "failed"
    assert mismatch_gate["checks"]["source_identity"]["passed"] is False

    required_image = {
        "observed": {"status": "unavailable"},
        "declared": {"id": "sha256:" + "a" * 64},
        "declared_matches_observed": None,
    }
    image_gate = PILOT._verifier_gate(
        measurements,
        runtime,
        source,
        required_image,
        image_required=True,
    )
    assert image_gate["status"] == "failed"
    assert image_gate["checks"]["image_identity"]["status"] == "mismatch_or_unavailable"

    matched_image = {
        "observed": {"id": "sha256:" + "a" * 64},
        "declared": {"id": "sha256:" + "a" * 64},
        "declared_matches_observed": True,
    }
    matched_image_gate = PILOT._verifier_gate(
        measurements,
        runtime,
        source,
        matched_image,
        image_required=True,
    )
    assert matched_image_gate["status"] == "passed"
    assert matched_image_gate["checks"]["image_identity"]["status"] == "matched"

    bad_runtime = {name: dict(row) for name, row in runtime.items()}
    bad_runtime["evidence_repair"] = {
        **bad_runtime["evidence_repair"],
        "effort": "high",
        "spans": {"cleanup": {"status": "failed"}},
    }
    runtime_gate = PILOT._verifier_gate(
        measurements,
        bad_runtime,
        source,
        image,
        image_required=False,
    )
    assert runtime_gate["status"] == "failed"
    assert runtime_gate["checks"]["exact_runtime_and_cleanup"]["passed"] is False
