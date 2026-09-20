import asyncio
import json
import os
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest

from rapido.config import ConfigError, RuntimeConfig
from rapido.offline_profile import (
    OFFLINE_PROFILE_SCHEMA,
    OfflineRuntimeConfig,
    OfflineTaskRegistration,
    assert_offline_environment,
    offline_child_env,
)
from rapido.offline_run import (
    OfflineRunRegistration,
    build_native_offline_plan,
)

_RUNNER_IMAGE = "sha256:0eef1ceb74759bf64e9a89ca0dd1cf722bd1f6967a9b53666577164ee4d71c52"


def _docker_image_available() -> bool:
    docker = shutil.which("docker")
    if docker is None:
        return False
    return (
        subprocess.run(
            (docker, "image", "inspect", _RUNNER_IMAGE),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode
        == 0
    )


def _config(tmp_path: Path) -> OfflineRuntimeConfig:
    return OfflineRuntimeConfig.build(
        offline_profile_id="capability-v1",
        catalogue_version="catalogue-v3",
        board_implementation_version="offline-board-v1",
        state_path=tmp_path / "state.sqlite3",
        work_root=tmp_path / "work",
        codex_home=tmp_path / "codex-home",
        runner_image=_RUNNER_IMAGE,
        task_registrations=(OfflineTaskRegistration(91, "EAS-005", "generator-v1", "checker-v1"),),
        active_challenges=1,
        attempts_per_challenge=2,
        lead_lanes=1,
        max_artifact_bytes=1024,
        max_challenge_bytes=2048,
        max_workspace_bytes=6144,
    )


def test_builds_offline_profile_without_production_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> RuntimeConfig:
        raise AssertionError("production parser was called")

    monkeypatch.setattr(RuntimeConfig, "from_env", forbidden)
    config = _config(tmp_path)

    assert config.board_url == ""
    assert config.board_token == ""
    assert config.team_key == ""
    assert config.profile == "capability-v1"
    assert config.challenge_ids == (91,)


def test_public_record_omits_authority_credentials_and_paths(tmp_path: Path) -> None:
    config = _config(tmp_path)
    record = config.public_record()
    encoded = repr(record)

    assert record["schema"] == OFFLINE_PROFILE_SCHEMA
    assert record["offline_profile_id"] == "capability-v1"
    assert record["board_timeout_seconds"] == 1
    assert record["instance_ready_seconds"] == 6
    assert record["instance_cleanup_seconds"] == 3
    for forbidden in (
        "board_url",
        "token",
        "team_key",
        "state_path",
        "work_root",
        "codex_home",
        str(tmp_path),
        "authority",
    ):
        assert forbidden not in encoded


@pytest.mark.parametrize("name", ["CTFD_URL", "CTFD_API_TOKEN", "TEAM_KEY"])
def test_offline_preflight_rejects_production_authority(name: str) -> None:
    with pytest.raises(ConfigError, match="authority variables"):
        assert_offline_environment({name: "present"})


def test_offline_child_environment_is_an_allowlist(tmp_path: Path) -> None:
    config = _config(tmp_path)
    child = offline_child_env(config, {"UNRELATED_SECRET": "not-forwarded"})

    assert set(child) == {"CODEX_HOME", "HOME", "PATH", "TERM", "NO_COLOR"}
    assert "UNRELATED_SECRET" not in repr(child)


def test_native_entry_plan_constructs_credential_free_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    observed: dict[str, object] = {}

    class Runtime:
        def __init__(self, **kwargs: object) -> None:
            observed.update(kwargs)

    class Boundary:
        def __init__(self, **kwargs: object) -> None:
            observed["boundary"] = kwargs

        async def process_factory(self, *_args: object, **_kwargs: object) -> None:
            return None

        async def verify(self) -> bool:
            return True

        async def cleanup_record(self) -> dict[str, object]:
            return {"process_absent": True, "active_process_count": 0}

    monkeypatch.setattr("rapido.offline_run._OfflineCodexClient", Runtime)
    monkeypatch.setattr("rapido.offline_run._DockerRuntimeBoundary", Boundary)
    private_root = tmp_path / "private-bank"
    private_root.mkdir(mode=0o700)
    registration = OfflineRunRegistration(
        config=config,
        board_factory=lambda: None,  # type: ignore[arg-type,return-value]
        run_root=tmp_path / "run",
        receipt_path=tmp_path / "receipt.json",
        private_roots=(private_root,),
        isolation_backend="docker-container-v1",
    )

    plan = build_native_offline_plan(registration)

    assert plan.runtime.__class__ is Runtime
    assert observed["env"] == offline_child_env(config, {})
    assert callable(observed["process_factory"])
    assert "CTFD" not in repr(observed)
    assert "TEAM_KEY" not in repr(observed)


@pytest.mark.skipif(not _docker_image_available(), reason="registered offline image unavailable")
def test_docker_native_boundary_uses_volumes_and_blocks_private_hardlink_alias(
    tmp_path: Path,
) -> None:
    from rapido.offline_run import _DockerRuntimeBoundary

    workspace = tmp_path / "run" / "work"
    codex_home = tmp_path / "codex-home"
    private = tmp_path / "private"
    workspace.mkdir(mode=0o700, parents=True)
    codex_home.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    auth = codex_home / "auth.json"
    auth.write_text("{}", encoding="utf-8")
    auth.chmod(0o600)
    oracle = private / "oracle"
    oracle.write_bytes(b"PRIVATE-ORACLE")
    os.link(oracle, workspace / "alias")
    lane = workspace / "challenge" / "lane-0"
    lane.mkdir(parents=True)
    (lane / "host.txt").write_text("host-visible", encoding="utf-8")
    boundary = _DockerRuntimeBoundary(
        workspace_root=workspace,
        codex_home=codex_home,
        private_roots=(private,),
        binary="/bin/sh",
        image=_RUNNER_IMAGE,
    )
    assert boundary._pin_workspace() is True

    async def exercise() -> None:
        assert await boundary.verify() is True
        await boundary.sync_workspace(lane)
        process = await boundary.process_factory(
            "ignored",
            "-c",
            (
                f"test ! -e {workspace / 'alias'} && "
                f"test -r {codex_home / 'auth.json'} && "
                f'test "$(cat {lane / "host.txt"})" = host-visible'
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await process.communicate()
        assert process.returncode == 0
        assert stdout == stderr == b""
        assert await boundary.cleanup_record() == {
            "process_absent": True,
            "active_process_count": 0,
        }

    asyncio.run(exercise())


@pytest.mark.skipif(not _docker_image_available(), reason="registered offline image unavailable")
def test_docker_native_boundary_cgroup_cleanup_contains_setsid_descendant(tmp_path: Path) -> None:
    from rapido.offline_run import _DockerRuntimeBoundary

    workspace = tmp_path / "run" / "work"
    codex_home = tmp_path / "codex-home"
    private = tmp_path / "private"
    workspace.mkdir(mode=0o700, parents=True)
    codex_home.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    auth = codex_home / "auth.json"
    auth.write_text("{}", encoding="utf-8")
    auth.chmod(0o600)
    boundary = _DockerRuntimeBoundary(
        workspace_root=workspace,
        codex_home=codex_home,
        private_roots=(private,),
        binary="/bin/sh",
        image=_RUNNER_IMAGE,
    )

    async def exercise() -> None:
        assert await boundary.verify() is True
        process = await boundary.process_factory(
            "ignored",
            "-c",
            "setsid sleep 60 & wait",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.sleep(0.2)
        code, raw = await boundary._docker_command("inspect", process.container_name)
        assert code == 0
        inspected = json.loads(raw)[0]
        assert {mount["Name"] for mount in inspected["Mounts"]} == {
            boundary.workspace_volume,
            boundary.codex_volume,
        }
        by_name = {mount["Name"]: mount for mount in inspected["Mounts"]}
        assert by_name[boundary.workspace_volume]["RW"] is False
        assert by_name[boundary.codex_volume]["RW"] is True
        assert set(inspected["HostConfig"]["Tmpfs"]) == {"/tmp", "/auth/codex", "/state"}
        assert await boundary.cleanup_record() == {
            "process_absent": True,
            "active_process_count": 0,
        }

    asyncio.run(exercise())


@pytest.mark.skipif(not _docker_image_available(), reason="registered offline image unavailable")
def test_native_workspace_capture_pins_parent_directory_during_symlink_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from rapido.offline_run import _DockerRuntimeBoundary

    workspace = tmp_path / "run" / "work"
    lane = workspace / "challenge" / "lane-0"
    private = tmp_path / "private"
    codex_home = tmp_path / "codex-home"
    lane.mkdir(mode=0o700, parents=True)
    private.mkdir(mode=0o700)
    codex_home.mkdir(mode=0o700)
    (codex_home / "auth.json").write_text("{}", encoding="utf-8")
    (lane / "visible.txt").write_bytes(b"safe")
    (private / "visible.txt").write_bytes(b"PRIVATE")
    original_listdir = os.listdir
    parked = lane.with_name("lane-0-pinned")
    swapped = False
    boundary = _DockerRuntimeBoundary(
        workspace_root=workspace,
        codex_home=codex_home,
        private_roots=(private,),
        binary="/bin/sh",
        image=_RUNNER_IMAGE,
    )
    assert boundary._pin_workspace() is True

    def swap_after_pin(path: object) -> list[str]:
        nonlocal swapped
        if isinstance(path, int) and not swapped:
            lane.rename(parked)
            lane.symlink_to(private, target_is_directory=True)
            swapped = True
        return original_listdir(path)  # type: ignore[arg-type]

    monkeypatch.setattr(os, "listdir", swap_after_pin)
    relative, payload = boundary._workspace_archive(lane)
    try:
        with tarfile.open(fileobj=payload, mode="r") as archive:
            extracted = archive.extractfile(f"{relative}/visible.txt")
            assert extracted is not None
            assert extracted.read() == b"safe"
            assert "PRIVATE" not in repr(archive.getnames())
    finally:
        payload.close()


@pytest.mark.skipif(not _docker_image_available(), reason="registered offline image unavailable")
def test_native_workspace_capture_rejects_work_root_identity_swap(tmp_path: Path) -> None:
    from rapido.offline_run import _DockerRuntimeBoundary

    workspace = tmp_path / "run" / "work"
    lane = workspace / "challenge" / "lane-0"
    codex_home = tmp_path / "codex-home"
    private = tmp_path / "private"
    replacement = tmp_path / "replacement-work"
    lane.mkdir(mode=0o700, parents=True)
    codex_home.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    (codex_home / "auth.json").write_text("{}", encoding="utf-8")
    replacement_lane = replacement / "challenge" / "lane-0"
    replacement_lane.mkdir(mode=0o700, parents=True)
    (lane / "visible").write_bytes(b"safe")
    (replacement_lane / "visible").write_bytes(b"PRIVATE")
    boundary = _DockerRuntimeBoundary(
        workspace_root=workspace,
        codex_home=codex_home,
        private_roots=(private,),
        binary="/bin/sh",
        image=_RUNNER_IMAGE,
    )
    assert boundary._pin_workspace() is True
    parked = workspace.with_name("work-pinned")
    workspace.rename(parked)
    replacement.rename(workspace)

    with pytest.raises(ConfigError, match="changed identity"):
        boundary._workspace_archive(lane)


@pytest.mark.skipif(not _docker_image_available(), reason="registered offline image unavailable")
def test_native_auth_capture_rejects_codex_home_identity_swap(tmp_path: Path) -> None:
    from rapido.offline_run import _DockerRuntimeBoundary

    workspace = tmp_path / "run" / "work"
    codex_home = tmp_path / "codex-home"
    private = tmp_path / "private"
    replacement = tmp_path / "replacement-codex"
    workspace.mkdir(mode=0o700, parents=True)
    codex_home.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    replacement.mkdir(mode=0o700)
    (codex_home / "auth.json").write_text("{}", encoding="utf-8")
    (replacement / "auth.json").write_text('{"token":"PRIVATE"}', encoding="utf-8")
    boundary = _DockerRuntimeBoundary(
        workspace_root=workspace,
        codex_home=codex_home,
        private_roots=(private,),
        binary="/bin/sh",
        image=_RUNNER_IMAGE,
    )
    parked = codex_home.with_name("codex-home-pinned")
    codex_home.rename(parked)
    replacement.rename(codex_home)

    try:
        assert asyncio.run(boundary._initialize_volumes()) is False
    finally:
        os.close(boundary._auth_descriptor)
        boundary._auth_descriptor = -1
        os.close(boundary._codex_descriptor)
        boundary._codex_descriptor = -1


@pytest.mark.skipif(not _docker_image_available(), reason="registered offline image unavailable")
def test_native_auth_capture_rejects_auth_file_identity_swap(tmp_path: Path) -> None:
    from rapido.offline_run import _DockerRuntimeBoundary

    workspace = tmp_path / "run" / "work"
    codex_home = tmp_path / "codex-home"
    private = tmp_path / "private"
    workspace.mkdir(mode=0o700, parents=True)
    codex_home.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    auth = codex_home / "auth.json"
    auth.write_text("{}", encoding="utf-8")
    private_auth = private / "auth.json"
    private_auth.write_text('{"token":"PRIVATE"}', encoding="utf-8")
    boundary = _DockerRuntimeBoundary(
        workspace_root=workspace,
        codex_home=codex_home,
        private_roots=(private,),
        binary="/bin/sh",
        image=_RUNNER_IMAGE,
    )
    auth.rename(codex_home / "auth-original.json")
    private_auth.rename(auth)

    try:
        assert asyncio.run(boundary._initialize_volumes()) is False
    finally:
        os.close(boundary._auth_descriptor)
        boundary._auth_descriptor = -1
        os.close(boundary._codex_descriptor)
        boundary._codex_descriptor = -1


@pytest.mark.skipif(not _docker_image_available(), reason="registered offline image unavailable")
def test_cancelled_native_docker_helper_is_reaped_and_owned_container_cleaned(
    tmp_path: Path,
) -> None:
    from rapido.offline_run import _DockerRuntimeBoundary

    workspace = tmp_path / "run" / "work"
    codex_home = tmp_path / "codex-home"
    private = tmp_path / "private"
    workspace.mkdir(mode=0o700, parents=True)
    codex_home.mkdir(mode=0o700)
    private.mkdir(mode=0o700)
    auth = codex_home / "auth.json"
    auth.write_text("{}", encoding="utf-8")
    auth.chmod(0o600)
    boundary = _DockerRuntimeBoundary(
        workspace_root=workspace,
        codex_home=codex_home,
        private_roots=(private,),
        binary="/bin/sh",
        image=_RUNNER_IMAGE,
    )

    async def exercise() -> None:
        assert await boundary.verify() is True
        name = f"rapido-offline-{boundary.run_token}-cancel-helper"
        task = asyncio.create_task(
            boundary._docker_command(
                "run",
                "--rm",
                "--name",
                name,
                "--label",
                boundary.stable_label,
                "--label",
                boundary.run_label,
                "--network",
                "none",
                "--tmpfs",
                "/auth/codex:size=1m",
                "--tmpfs",
                "/state:size=1m",
                "--entrypoint",
                "/bin/sh",
                boundary.image,
                "-c",
                "sleep 60",
                timeout=60,
            )
        )
        limit = asyncio.get_running_loop().time() + 5
        while not boundary._helpers and asyncio.get_running_loop().time() < limit:
            await asyncio.sleep(0.01)
        assert boundary._helpers
        cleanup_task = asyncio.create_task(boundary.cleanup_record())
        await asyncio.sleep(0)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        assert boundary._helpers == []
        assert await asyncio.wait_for(cleanup_task, timeout=10.0) == {
            "process_absent": True,
            "active_process_count": 0,
        }

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ({"offline_profile_id": "Offline Profile"}, "closed identifier"),
        ({"task_registrations": ()}, "task registrations"),
        (
            {
                "task_registrations": (
                    OfflineTaskRegistration(1, "EAS-005", "generator-v1", "checker-v1"),
                    OfflineTaskRegistration(1, "EAS-006", "generator-v1", "checker-v1"),
                )
            },
            "task registrations",
        ),
        ({"active_challenges": 2}, "active challenge"),
        ({"specialist_reasoning_efforts": ()}, "specialist efforts"),
        ({"attempt_seconds": 599}, "time budget"),
        ({"max_workspace_bytes": 4096}, "workspace budget"),
    ],
)
def test_offline_registration_rejects_unsafe_values(
    tmp_path: Path, replacement: dict[str, object], message: str
) -> None:
    values: dict[str, object] = {
        "offline_profile_id": "capability-v1",
        "catalogue_version": "catalogue-v3",
        "board_implementation_version": "offline-board-v1",
        "state_path": tmp_path / "state.sqlite3",
        "work_root": tmp_path / "work",
        "codex_home": tmp_path / "codex-home",
        "runner_image": _RUNNER_IMAGE,
        "task_registrations": (
            OfflineTaskRegistration(91, "EAS-005", "generator-v1", "checker-v1"),
        ),
        "active_challenges": 1,
        "attempts_per_challenge": 2,
        "lead_lanes": 1,
        "max_artifact_bytes": 1024,
        "max_challenge_bytes": 2048,
        "max_workspace_bytes": 6144,
    }
    values.update(replacement)
    with pytest.raises(ConfigError, match=message):
        OfflineRuntimeConfig.build(**values)  # type: ignore[arg-type]
