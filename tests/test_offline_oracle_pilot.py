from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from rapido.codex_app import ModelValidationError
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


def _patch_source_observation(monkeypatch: pytest.MonkeyPatch) -> None:
    def completed(command: list[str], **_: object) -> SimpleNamespace:
        if command[1:3] == ["rev-parse", "--verify"]:
            return SimpleNamespace(stdout="c" * 40 + "\n")
        assert command[1:3] == ["status", "--porcelain=v1"]
        return SimpleNamespace(stdout=" M rapido/example.py\n?? scripts/new.py\n")

    monkeypatch.setattr(PILOT.subprocess, "run", completed)


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
