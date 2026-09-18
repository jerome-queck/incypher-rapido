from __future__ import annotations

import asyncio
import os
import time
from pathlib import Path

import pytest

from rapido.board import Challenge
from rapido.config import RuntimeConfig
from rapido.orchestrator import Orchestrator, _challenge_material_sha256
from rapido.routing import baseline_route
from rapido.state import StateStore
from rapido.target import TargetEndpoint


class _OfflineBoard:
    timeout = 0.01

    def __init__(self, payload: bytes = b"attached artifact") -> None:
        self.payload = payload

    def download(self, _file_ref: str, destination: Path, *, byte_limit: int) -> dict[str, int]:
        payload = self.payload[:byte_limit]
        destination.write_bytes(payload)
        return {"bytes": len(payload)}


@pytest.fixture
def carry_harness(tmp_path: Path):
    auth = tmp_path / "auth"
    auth.mkdir()
    config = RuntimeConfig.from_env(
        {
            "RAPIDO_STATE_PATH": str(tmp_path / "state.sqlite3"),
            "RAPIDO_WORK_ROOT": str(tmp_path / "work"),
            "RAPIDO_CODEX_HOME": str(auth),
            "RAPIDO_ACTIVE_CHALLENGES": "1",
            "RAPIDO_ATTEMPTS_PER_CHALLENGE": "2",
            "RAPIDO_CONCURRENCY": "2",
            "RAPIDO_MAX_ARTIFACT_BYTES": "1024",
            "RAPIDO_MAX_CHALLENGE_BYTES": "1024",
            "RAPIDO_MAX_WORKSPACE_BYTES": "10000",
            "RAPIDO_MANAGE_DYNAMIC_INSTANCES": "false",
            "RAPIDO_WATCH_BOARD": "false",
            "RAPIDO_MEMORY_ARM": "lane_local_v1",
        }
    )
    item = Challenge(
        7,
        "Carry fixture",
        "crypto",
        "standard",
        "derive the value",
        100,
        ("/files/input.bin",),
        False,
        None,
        0,
        None,
        None,
    )
    state = StateStore(config.state_path)
    state.start_run("run-a", config.public_record())
    state.upsert_challenge(item.id, item.name, item.category, item.type, item.value)
    route = baseline_route(
        model=config.model,
        effort=config.reasoning_effort,
        attempt_seconds=config.attempt_seconds,
    )
    state.initialize_control_catalogue(
        "run-a",
        [(0, item.id, True)],
        lanes=2,
        route=route,
        assignments=(
            ("specialist", config.model, config.reasoning_effort),
            ("specialist", config.model, config.reasoning_effort),
        ),
        context_sha256s={item.id: _challenge_material_sha256(item)},
    )
    root = tmp_path / "run-a"
    orchestrator = Orchestrator(config, _OfflineBoard(), state, object())
    yield orchestrator, state, item, root
    state.close()


def _prepare(
    orchestrator: Orchestrator,
    root: Path,
    item: Challenge,
    *,
    episode: int,
    generation: int = 0,
    lane_count: int = 2,
    allow_analysis_carry: bool = True,
) -> list[tuple[Path, list[str]]]:
    return asyncio.run(
        orchestrator._prepare_workspaces(
            "run-a",
            root,
            item,
            episode,
            time.monotonic() + 30,
            workspace_generation=generation,
            lane_count=lane_count,
            allow_analysis_carry=allow_analysis_carry,
        )
    )


def _capture(
    orchestrator: Orchestrator, state: StateStore, item: Challenge, root: Path, episode: int = 0
) -> tuple[int, int, Path]:
    files, byte_count, _telemetry = orchestrator._capture_analysis_carry(
        "run-a", item, episode, root, ()
    )
    material = state.control_catalogue_contexts("run-a")[item.id]
    return files, byte_count, root / f"challenge-{item.id}" / "carry" / material


def test_safe_same_run_material_scripts_survive_next_non_verifier_generation(
    carry_harness,
) -> None:
    orchestrator, state, item, root = carry_harness
    for lane, (workspace, _) in enumerate(_prepare(orchestrator, root, item, episode=0)):
        script = workspace / "rapido-analysis" / "solve.py"
        script.parent.mkdir()
        script.write_text(f"print('derived lane {lane}')\n")

    files, byte_count, carry_root = _capture(orchestrator, state, item, root)
    assert files == 2
    assert byte_count == len(b"print('derived lane 0')\n") + len(b"print('derived lane 1')\n")

    successor_workspaces = _prepare(orchestrator, root, item, episode=1)
    for lane, (workspace, paths) in enumerate(successor_workspaces):
        carried = workspace / "rapido-analysis" / "carried" / "solve.py"
        assert carried.read_text() == f"print('derived lane {lane}')\n"
        assert "rapido-analysis/carried/solve.py" in paths
        assert (carry_root / f"lane-{lane}" / "solve.py").read_text() == carried.read_text()


def test_endpoint_flag_credentials_and_escape_links_are_not_carried(
    carry_harness, tmp_path: Path
) -> None:
    orchestrator, state, item, root = carry_harness
    workspace, _ = _prepare(orchestrator, root, item, episode=0, lane_count=1)[0]
    analysis = workspace / "rapido-analysis"
    analysis.mkdir()
    (analysis / "safe.py").write_text("print('source-bound derivation')\n")
    (analysis / "endpoint.py").write_bytes(b"target authority target.example:8080")
    (analysis / "flag.txt").write_bytes(b"INCYPHER{candidate-material}")
    (analysis / "credentials.txt").write_bytes(b"password=private-value")

    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "outside.py"
    outside_file.write_text("print('outside')\n")
    (analysis / "symlink.py").symlink_to(outside_file)
    os.link(outside_file, analysis / "hardlink.py")
    (analysis / "escaped").symlink_to(outside, target_is_directory=True)

    result = orchestrator._capture_analysis_carry(
        "run-a",
        item,
        0,
        root,
        (TargetEndpoint("http", "target.example", 8080),),
    )
    material = state.control_catalogue_contexts("run-a")[item.id]
    carry_root = root / f"challenge-{item.id}" / "carry" / material
    assert result[0] == 1
    carried = sorted(
        path.relative_to(carry_root) for path in carry_root.rglob("*") if path.is_file()
    )
    assert carried == [Path("lane-0/safe.py")]
    assert outside_file.read_text() == "print('outside')\n"


def test_verifier_generation_receives_no_analysis_carry(carry_harness) -> None:
    orchestrator, state, item, root = carry_harness
    workspace, _ = _prepare(orchestrator, root, item, episode=0, lane_count=1)[0]
    script = workspace / "rapido-analysis" / "solve.py"
    script.parent.mkdir()
    script.write_text("print('safe carry')\n")
    assert _capture(orchestrator, state, item, root)[0] == 1

    verifier_workspace, paths = _prepare(
        orchestrator,
        root,
        item,
        episode=1,
        lane_count=1,
        allow_analysis_carry=False,
    )[0]
    assert not (verifier_workspace / "rapido-analysis").exists()
    assert all(not path.startswith("rapido-analysis/") for path in paths)


def test_latest_generation_replaces_stale_lane_content(carry_harness) -> None:
    orchestrator, state, item, root = carry_harness
    old_workspace, _ = _prepare(orchestrator, root, item, episode=0, generation=0, lane_count=1)[0]
    old_script = old_workspace / "rapido-analysis" / "stale.py"
    old_script.parent.mkdir()
    old_script.write_text("print('stale')\n")
    _, _, carry_root = _capture(orchestrator, state, item, root)
    assert (carry_root / "lane-0" / "stale.py").read_text() == "print('stale')\n"

    new_workspace = root / "challenge-7" / "episode-0" / "generation-1" / "lane-0"
    new_script = new_workspace / "rapido-analysis" / "latest.py"
    new_script.parent.mkdir(parents=True)
    new_script.write_text("print('latest')\n")
    files, _, carry_root = _capture(orchestrator, state, item, root)

    assert files == 1
    assert (carry_root / "lane-0" / "latest.py").read_text() == "print('latest')\n"
    assert not (carry_root / "lane-0" / "stale.py").exists()
    successor_workspace, _ = _prepare(orchestrator, root, item, episode=1, lane_count=1)[0]
    assert (
        successor_workspace / "rapido-analysis" / "carried" / "latest.py"
    ).read_text() == "print('latest')\n"


def test_repeated_carry_roundtrips_keep_one_canonical_path(carry_harness) -> None:
    orchestrator, state, item, root = carry_harness
    workspace, _ = _prepare(orchestrator, root, item, episode=0, lane_count=1)[0]
    script = workspace / "rapido-analysis" / "solve.py"
    script.parent.mkdir()
    script.write_text("print('stable')\n")
    _capture(orchestrator, state, item, root, episode=0)

    for episode in (1, 2, 3):
        workspace, _ = _prepare(orchestrator, root, item, episode=episode, lane_count=1)[0]
        imported = workspace / "rapido-analysis" / "carried" / "solve.py"
        assert imported.read_text() == "print('stable')\n"
        files, _, carry_root = _capture(orchestrator, state, item, root, episode=episode)
        assert files == 1
        carried_files = [path for path in carry_root.rglob("*") if path.is_file()]
        assert [path.relative_to(carry_root) for path in carried_files] == [Path("lane-0/solve.py")]


def test_global_carry_cap_is_round_robin_fair_and_deterministic(carry_harness) -> None:
    orchestrator, state, item, root = carry_harness
    workspaces = _prepare(orchestrator, root, item, episode=0, lane_count=4)
    for lane, (workspace, _) in enumerate(workspaces):
        analysis = workspace / "rapido-analysis"
        analysis.mkdir()
        for index in range(20):
            (analysis / f"item-{index:02d}.txt").write_text(f"lane {lane} item {index}\n")

    files, _, telemetry = orchestrator._capture_analysis_carry("run-a", item, 0, root, ())
    material = state.control_catalogue_contexts("run-a")[item.id]
    carry_root = root / f"challenge-{item.id}" / "carry" / material
    retained = {
        lane: sorted(path.name for path in (carry_root / f"lane-{lane}").iterdir())
        for lane in range(4)
    }

    assert files == 64
    assert {lane: len(paths) for lane, paths in retained.items()} == {
        0: 16,
        1: 16,
        2: 16,
        3: 16,
    }
    assert telemetry["drop_counts"] == {"file_cap": 16}
    assert [row["retained"] for row in telemetry["lane_counts"]] == [16, 16, 16, 16]
