"""Secret-free tests for the sealed H24 Docker supervisor."""

from __future__ import annotations

import fcntl
import importlib.util
import json
import os
import shutil
import stat
import sys
import time
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from rapido.offline_h24_evaluation import (
    REGISTRATION_SCHEMA,
    build_frozen_preregistration,
    preregistration_sha256,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "offline_h24_supervisor", ROOT / "scripts" / "offline_h24_supervisor.py"
)
assert SPEC is not None and SPEC.loader is not None
SUPERVISOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = SUPERVISOR
SPEC.loader.exec_module(SUPERVISOR)

SOURCE_SHA = "1" * 40
TREE_SHA = "2" * 40
IMAGE_ID = "sha256:" + "3" * 64
PROBE_ID = "4" * 64
H24_ID = "5" * 64
SOAK_ID = "6" * 64
DESCRIPTOR_ID = "7" * 64
IMAGE_VOLUME_DESTINATIONS = ("/auth/codex", "/state")


def _anonymous_volume(
    destination: str, marker: str, *, data_root: str = "/var/lib/docker/volumes"
) -> dict[str, object]:
    name = marker if len(marker) == 64 else marker * 64
    return {
        "Type": "volume",
        "Name": name,
        "Source": f"{data_root}/{name}/_data",
        "Destination": destination,
        "Driver": "local",
        "Mode": "",
        "RW": True,
        "Propagation": "",
    }


def _volume_metadata(mount: dict[str, object], *, anonymous: bool = True) -> dict[str, object]:
    return {
        "CreatedAt": "2026-09-19T19:57:14+08:00",
        "Driver": "local",
        "Labels": {"com.docker.volume.anonymous": ""} if anonymous else {},
        "Mountpoint": mount["Source"],
        "Name": mount["Name"],
        "Options": None,
        "Scope": "local",
    }


def _private_directory(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _private_file(path: Path, value: bytes) -> Path:
    path.write_bytes(value)
    path.chmod(0o600)
    return path


def _registration(preregistration: dict[str, object]) -> dict[str, object]:
    return {
        "schema": REGISTRATION_SCHEMA,
        "preregistration_sha256": preregistration_sha256(preregistration),
        "registered_at_utc": "2026-09-19T00:00:00Z",
        "registration_state": "frozen_after_pr6_merge_before_outcomes",
        "source": {
            "commit_sha": SOURCE_SHA,
            "tree_sha": TREE_SHA,
            "worktree_status": "clean",
            "pr6_squash_merge_commit_sha": SOURCE_SHA,
        },
        "image": {
            "id": IMAGE_ID,
            "platform": "linux/arm64",
            "build_source_commit_sha": SOURCE_SHA,
            "immutable": True,
        },
    }


def _protocol_files(tmp_path: Path) -> tuple[Any, Path, Path]:
    preregistration = build_frozen_preregistration()
    preregistration_path = tmp_path / "preregistration.json"
    preregistration_path.write_text(json.dumps(preregistration))
    registration_path = tmp_path / "registration.json"
    registration_path.write_text(json.dumps(_registration(preregistration)))
    registration_path.chmod(0o444)
    protocol = SUPERVISOR.bind_registration(
        registration_path, SUPERVISOR.load_protocol(preregistration_path)
    )
    return protocol, preregistration_path, registration_path


def _paths(tmp_path: Path, preregistration: Path, registration: Path) -> Any:
    repository = _private_directory(tmp_path / "repository")
    auth = _private_directory(tmp_path / "auth")
    _private_file(auth / "auth.json", b'{"tokens":{}}')
    work = _private_directory(tmp_path / "work")
    output = _private_directory(tmp_path / "output")
    seed = _private_file(tmp_path / "seed", b"s" * 32)
    return SUPERVISOR.Paths(
        repository,
        preregistration,
        registration,
        auth,
        work,
        seed,
        output,
    )


class FakeClock:
    def __init__(self) -> None:
        self.value = 1_000.0
        self.wall = 2_000_000_000.0

    def monotonic(self) -> float:
        return self.value

    def time(self) -> float:
        return self.wall + self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class DockerFake:
    def __init__(
        self,
        output: Path,
        *,
        keep_soak_running: bool = False,
        keep_h24_running: bool = False,
        oom: bool = False,
        clock: FakeClock | None = None,
    ) -> None:
        self.output = output
        self.keep_soak_running = keep_soak_running
        self.keep_h24_running = keep_h24_running
        self.oom = oom
        self.clock = clock
        self.commands: list[tuple[str, ...]] = []
        self.command_times: list[tuple[tuple[str, ...], float]] = []
        self.existing: set[str] = set()
        self.running: set[str] = set()
        self.names: dict[str, str] = {}
        self.configs: dict[str, dict[str, object]] = {}
        self.volumes: dict[str, dict[str, object]] = {}

    def _id_for_name(self, name: str) -> str:
        return {
            SUPERVISOR._H24_NAME: H24_ID,
            SUPERVISOR._SOAK_NAME: SOAK_ID,
            f"{SUPERVISOR._H24_NAME}-descriptor": DESCRIPTOR_ID,
        }[name]

    def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
        del timeout
        command = tuple(argv)
        self.commands.append(command)
        self.command_times.append((command, self.clock.monotonic() if self.clock else -1.0))
        if command[:3] == ("docker", "ps", "--all") and "--quiet" not in command:
            name = command[command.index("--filter") + 1].removeprefix("name=^/").removesuffix("$")
            matches = [container_id for container_id, value in self.names.items() if value == name]
            return SUPERVISOR.CommandResult(0, f"{name}\n" if matches else "")
        if command == ("docker", "ps", "--all", "--quiet"):
            return SUPERVISOR.CommandResult(0, "\n".join(sorted(self.existing)))
        if command[:5] == ("docker", "ps", "--all", "--quiet", "--no-trunc"):
            filter_value = command[command.index("--filter") + 1]
            if filter_value.startswith("label="):
                key, expected = filter_value.removeprefix("label=").split("=", 1)
                matches = [
                    container_id
                    for container_id in self.existing
                    if self.configs[container_id]["labels"].get(key) == expected
                ]
            else:
                expected = filter_value.removeprefix("id=")
                matches = [value for value in self.existing if value == expected]
            return SUPERVISOR.CommandResult(0, "\n".join(sorted(matches)))
        if command[:2] == ("docker", "create"):
            name = command[command.index("--name") + 1]
            container_id = self._id_for_name(name)
            labels: dict[str, str] = {}
            for index, value in enumerate(command):
                if value == "--label":
                    key, label_value = command[index + 1].split("=", 1)
                    labels[key] = label_value
            mounts: list[dict[str, object]] = []
            for index, value in enumerate(command):
                if value != "--mount":
                    continue
                fields = dict(
                    item.split("=", 1) if "=" in item else (item, "")
                    for item in command[index + 1].split(",")
                )
                mounts.append(
                    {
                        "Type": fields["type"],
                        "Source": fields["src"],
                        "Destination": fields["dst"],
                        "RW": "readonly" not in fields,
                    }
                )
            bound_destinations = {mount["Destination"] for mount in mounts}
            for index, destination in enumerate(IMAGE_VOLUME_DESTINATIONS):
                if destination not in bound_destinations:
                    volume = _anonymous_volume(destination, f"{container_id[:-1]}{index:x}")
                    mounts.append(volume)
                    self.volumes[str(volume["Name"])] = _volume_metadata(volume)
            self.existing.add(container_id)
            self.names[container_id] = name
            self.configs[container_id] = {
                "labels": labels,
                "mounts": mounts,
                "volumes": {destination: {} for destination in IMAGE_VOLUME_DESTINATIONS},
            }
            return SUPERVISOR.CommandResult(0, f"{container_id}\n")
        if command[:3] == ("docker", "volume", "inspect"):
            names = command[3:]
            if any(name not in self.volumes for name in names):
                return SUPERVISOR.CommandResult(1, "[]")
            return SUPERVISOR.CommandResult(
                0,
                json.dumps([self.volumes[name] for name in names]),
            )
        if command[:4] == ("docker", "volume", "ls", "--quiet"):
            expected = command[-1].removeprefix("name=^").removesuffix("$")
            return SUPERVISOR.CommandResult(0, f"{expected}\n" if expected in self.volumes else "")
        if command[:2] == ("docker", "start") and "--attach" not in command:
            self.running.update(command[2:])
            return SUPERVISOR.CommandResult(0, "started\n")
        if command[:2] == ("docker", "stats"):
            container_ids = command[command.index("--format={{json .}}") + 1 :]
            rows = [
                json.dumps(
                    {
                        "ID": container_id,
                        "Name": self.names[container_id],
                        "CPUPerc": "125.5%",
                        "MemUsage": "256MiB / 20GiB",
                        "PIDs": "17",
                    }
                )
                for container_id in container_ids
            ]
            return SUPERVISOR.CommandResult(0, "\n".join(rows))
        if command[:3] == ("docker", "container", "inspect"):
            container_id = command[-1]
            name = self.names[container_id]
            running = container_id in self.running
            if (container_id == H24_ID and not self.keep_h24_running) or (
                container_id == SOAK_ID and not self.keep_soak_running
            ):
                running = False
                self.running.discard(container_id)
            state = {
                "Running": running,
                "ExitCode": 0,
                "OOMKilled": self.oom and name.endswith("eval"),
            }
            if command[3] == "--format={{json .State}}":
                return SUPERVISOR.CommandResult(0, json.dumps(state))
            return SUPERVISOR.CommandResult(
                0,
                json.dumps(
                    {
                        "Id": container_id,
                        "Name": f"/{name}",
                        "Image": IMAGE_ID,
                        "Config": {
                            "User": SUPERVISOR.CONTAINER_USER,
                            "Labels": self.configs[container_id]["labels"],
                            "Volumes": self.configs[container_id]["volumes"],
                        },
                        "State": state,
                        "Mounts": self.configs[container_id]["mounts"],
                    }
                ),
            )
        if command[:2] == ("docker", "stop"):
            self.running.difference_update(command[4:])
            return SUPERVISOR.CommandResult(0, "stopped\n")
        if command[:2] == ("docker", "logs"):
            return SUPERVISOR.CommandResult(0, "private raw child log\n")
        if command[:2] == ("docker", "rm"):
            container_id = command[-1]
            for mount in self.configs[container_id]["mounts"]:
                if mount["Type"] != "volume":
                    continue
                name = str(mount["Name"])
                metadata = self.volumes.get(name)
                if metadata is not None and metadata["Labels"] == {
                    "com.docker.volume.anonymous": ""
                }:
                    self.volumes.pop(name)
            self.existing.discard(container_id)
            self.running.discard(container_id)
            return SUPERVISOR.CommandResult(0, "removed\n")
        raise AssertionError(command)


def _seed_descriptor_receipt(output: Path, protocol: Any) -> None:
    value = {
        "schema": SUPERVISOR.DESCRIPTOR_SCHEMA,
        "preregistration_sha256": preregistration_sha256(protocol.preregistration),
        "source": {
            "observed": {
                "head_sha": protocol.source_sha,
                "worktree": "packaged_source",
                "tracked_change_count": None,
                "untracked_file_count": None,
            },
            "declared": {"sha": protocol.source_sha},
            "declared_matches_head": True,
            "identity_basis": "sealed_metadata_file",
        },
        "image": {
            "observed": {"id": protocol.image_id},
            "declared": {"id": protocol.image_id},
            "declared_matches_observed": True,
        },
        "descriptors": protocol.preregistration["descriptor_preflight"],
        "matched": True,
    }
    path = output / SUPERVISOR.DESCRIPTOR_RECEIPT
    path.write_text(json.dumps(value))
    path.chmod(0o600)


def _seed_child_receipts(output: Path, protocol: Any) -> None:
    _seed_descriptor_receipt(output, protocol)
    for name, schema in (
        (SUPERVISOR.H24_RECEIPT, "rapido-offline-h24-pilot-v1"),
        (SUPERVISOR.SOAK_RECEIPT, "rapido-benign-board-contract-v1"),
    ):
        path = output / name
        path.write_text(json.dumps({"schema": schema}))
        path.chmod(0o600)


def test_loader_uses_frozen_preregistration_and_external_registration(tmp_path: Path) -> None:
    protocol, _, _ = _protocol_files(tmp_path)
    assert protocol.source_sha == SOURCE_SHA
    assert protocol.source_tree_sha == TREE_SHA
    assert protocol.image_reference == IMAGE_ID
    assert protocol.image_id == IMAGE_ID
    assert protocol.image_platform == "linux/arm64"
    assert protocol.scoring_seconds == 19_800
    assert protocol.h24 == SUPERVISOR.Resources(10, 20, 256)
    assert protocol.soak == SUPERVISOR.Resources(1, 2, 64)


def test_registration_mismatch_fails_closed(tmp_path: Path) -> None:
    preregistration = build_frozen_preregistration()
    preregistration_path = tmp_path / "pre.json"
    preregistration_path.write_text(json.dumps(preregistration))
    registration = _registration(preregistration)
    registration["source"]["tree_sha"] = "bad"  # type: ignore[index]
    registration_path = tmp_path / "reg.json"
    registration_path.write_text(json.dumps(registration))
    with pytest.raises(SUPERVISOR.SupervisorError, match="registration_invalid"):
        SUPERVISOR.bind_registration(
            registration_path, SUPERVISOR.load_protocol(preregistration_path)
        )


@pytest.mark.parametrize("registration_offset", [30, 60])
def test_nonpreceding_registration_is_rejected_before_any_docker_call(
    tmp_path: Path, registration_offset: int
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    clock = FakeClock()
    protocol = replace(
        protocol,
        registration_time=datetime.fromtimestamp(clock.time() + registration_offset, tz=UTC),
    )
    calls: list[tuple[str, ...]] = []

    def no_docker(argv: Any, *, timeout: float | None = None) -> Any:
        del timeout
        calls.append(tuple(argv))
        raise AssertionError("registration time must fail before Docker access")

    with pytest.raises(SUPERVISOR.SupervisorError, match="registration_timing"):
        SUPERVISOR.run_evaluation(
            protocol,
            paths,
            runner=no_docker,
            clock=clock,
            finalize=False,
        )
    assert calls == []

    with pytest.raises(SUPERVISOR.SupervisorError, match="registration_timing"):
        SUPERVISOR.run_descriptor_preflight(
            protocol,
            paths,
            runner=no_docker,
            clock=clock,
        )
    assert calls == []


def test_cli_rejects_future_registration_before_source_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    protocol = replace(
        protocol,
        registration_time=datetime.fromtimestamp(time.time() + 60, tz=UTC),
    )
    arguments = SimpleNamespace(
        mode="execute",
        repository=paths.repository,
        preregistration=paths.preregistration,
        registration=paths.registration,
        auth=paths.auth,
        work=paths.work,
        seed=paths.seed,
        output=paths.output,
    )
    monkeypatch.setattr(SUPERVISOR, "_arguments", lambda: arguments)
    monkeypatch.setattr(SUPERVISOR, "validate_paths", lambda *_args, **_kwargs: paths)
    monkeypatch.setattr(SUPERVISOR, "load_protocol", lambda _path: protocol)
    monkeypatch.setattr(SUPERVISOR, "bind_registration", lambda _path, _protocol: protocol)
    monkeypatch.setattr(SUPERVISOR, "validate_environment", lambda _environment: None)
    monkeypatch.setattr(
        SUPERVISOR,
        "validate_source",
        lambda *_args: pytest.fail("source validation must follow timing validation"),
    )

    with pytest.raises(SUPERVISOR.SupervisorError, match="registration_timing"):
        SUPERVISOR.main()


def test_wrapper_dockerfile_is_separate_pinned_and_minimal() -> None:
    text = (ROOT / "deploy" / "Dockerfile.offline-eval").read_text()
    assert "ARG RAPIDO_BASE_IMAGE" in text
    assert "FROM ${RAPIDO_BASE_IMAGE}" in text
    assert 'io.incypher.rapido.base-reference="${RAPIDO_BASE_IMAGE}"' in text
    assert "grep -Eq '^(sha256:[0-9a-f]{64}|[^[:space:]@]+@sha256:[0-9a-f]{64})$'" in text
    assert "org.opencontainers.image.revision" in text
    assert "USER 10001:10001" in text
    assert "ENTRYPOINT" not in text
    assert "chmod 0444" in text
    assert "-name '*.pyc' -o -name '*.pyo'" in text
    assert "-name __pycache__ -empty -delete" in text
    assert text.index("-name '*.pyc'") < text.rindex("USER 10001:10001")
    copies = [line for line in text.splitlines() if line.startswith("COPY ")]
    assert len(copies) == 3
    assert any("offline_oracle_pilot.py" in line for line in copies)
    assert any("board_contract_soak.py" in line for line in copies)
    assert any("offline-h24-preregistration-v1.json" in line for line in copies)


def test_fixed_argv_boundaries_and_resources(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    ownership_token = "a" * 64
    h24 = SUPERVISOR.h24_create_argv(protocol, paths, ownership_token=ownership_token)
    soak = SUPERVISOR.soak_create_argv(protocol, paths, ownership_token=ownership_token)
    descriptor = SUPERVISOR.descriptor_preflight_argv(
        protocol, paths, ownership_token=ownership_token
    )

    for argv in (h24, soak, descriptor):
        assert "--init" not in argv
        assert "--read-only" in argv
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges:true" in argv
        assert argv[argv.index("--user") + 1] == "10001:10001"
        assert argv[argv.index("--label") + 1].endswith(ownership_token)
        assert argv[argv.index("--stop-timeout") + 1] == "190"
        assert "--h24-preregistration-file" in argv or "board_contract_soak.py" in " ".join(argv)
        assert not any("CTFD" in item or "TEAM_KEY" in item for item in argv)
    assert h24[h24.index("--cpus") + 1] == "10"
    assert h24[h24.index("--memory") + 1] == "20g"
    assert h24[h24.index("--pids-limit") + 1] == "256"
    assert "--network" not in h24
    assert "/seed/oracle.key" in h24
    assert "--network" in soak and soak[soak.index("--network") + 1] == "none"
    assert soak[soak.index("--duration-seconds") + 1] == "19800"
    assert "/auth/codex" not in soak
    assert "--descriptor-preflight" in descriptor
    assert "--oracle-key-file" not in descriptor
    assert "/seed/oracle.key" not in descriptor


def test_path_privacy_disjointness_capability_and_freshness(tmp_path: Path) -> None:
    _, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    validated = SUPERVISOR.validate_paths(paths, owner_uid=os.getuid())
    assert validated.auth == paths.auth.resolve()

    (paths.auth / "config.toml").write_text("capability = true")
    with pytest.raises(SUPERVISOR.SupervisorError, match="auth_capability_file"):
        SUPERVISOR.validate_paths(paths, owner_uid=os.getuid())


def test_private_paths_reject_public_modes_and_overlap(tmp_path: Path) -> None:
    _, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    paths.seed.chmod(0o644)
    with pytest.raises(SUPERVISOR.SupervisorError, match="seed_invalid"):
        SUPERVISOR.validate_paths(paths, owner_uid=os.getuid())
    paths.seed.chmod(0o600)
    overlap = replace(paths, work=paths.auth)
    with pytest.raises(SUPERVISOR.SupervisorError, match="private_path_overlap"):
        SUPERVISOR.validate_paths(overlap, owner_uid=os.getuid())


def test_external_registration_requires_material_immutability(tmp_path: Path) -> None:
    _, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    registration.chmod(0o644)
    with pytest.raises(SUPERVISOR.SupervisorError, match="registration_file_invalid"):
        SUPERVISOR.validate_paths(paths, owner_uid=os.getuid())


def test_auth_lease_rejects_symlink_and_hardlink_without_mutating_targets(
    tmp_path: Path,
) -> None:
    _, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    lock = paths.auth / ".offline-h24-supervisor.lock"
    victim = tmp_path / "victim"
    victim.write_text("unchanged")
    victim.chmod(0o644)
    lock.symlink_to(victim)

    with (
        pytest.raises(SUPERVISOR.SupervisorError, match="auth_lease_invalid"),
        SUPERVISOR.auth_lease(paths.auth),
    ):
        pass
    assert lock.is_symlink()
    assert victim.read_text() == "unchanged"
    assert stat.S_IMODE(victim.stat().st_mode) == 0o644

    lock.unlink()
    lock.write_text("lock")
    lock.chmod(0o600)
    second_link = paths.auth / "second-lock-link"
    os.link(lock, second_link)
    with (
        pytest.raises(SUPERVISOR.SupervisorError, match="auth_lease_invalid"),
        SUPERVISOR.auth_lease(paths.auth),
    ):
        pass
    assert lock.exists() and second_link.exists()


def test_auth_lease_busy_and_replacement_paths_are_never_unlinked(tmp_path: Path) -> None:
    _, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    lock = paths.auth / ".offline-h24-supervisor.lock"
    lock.write_text("lock")
    lock.chmod(0o600)
    held = os.open(lock, os.O_RDWR)
    fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
    try:
        with (
            pytest.raises(SUPERVISOR.SupervisorError, match="auth_lease_busy"),
            SUPERVISOR.auth_lease(paths.auth),
        ):
            pass
        assert lock.exists()
    finally:
        fcntl.flock(held, fcntl.LOCK_UN)
        os.close(held)
    lock.unlink()

    replacement_contents = "replacement"
    with (
        pytest.raises(SUPERVISOR.SupervisorError, match="auth_lease_integrity"),
        SUPERVISOR.auth_lease(paths.auth),
    ):
        lock.unlink()
        lock.write_text(replacement_contents)
        lock.chmod(0o600)
    assert lock.read_text() == replacement_contents


def test_board_environment_fails_closed() -> None:
    SUPERVISOR.validate_environment({"PATH": "/bin"})
    with pytest.raises(SUPERVISOR.SupervisorError, match="board_environment_present"):
        SUPERVISOR.validate_environment({"CTFD_API_TOKEN": "private"})


def test_source_requires_exact_clean_commit_and_tree(tmp_path: Path) -> None:
    calls: list[tuple[str, ...]] = []

    def runner(argv: Any, *, timeout: float | None = None) -> Any:
        del timeout
        command = tuple(argv)
        calls.append(command)
        if command[-2:] == ("rev-parse", "HEAD"):
            return SUPERVISOR.CommandResult(0, SOURCE_SHA + "\n")
        if command[-2:] == ("rev-parse", "HEAD^{tree}"):
            return SUPERVISOR.CommandResult(0, TREE_SHA + "\n")
        return SUPERVISOR.CommandResult(0, "")

    SUPERVISOR.validate_source(tmp_path, SOURCE_SHA, TREE_SHA, runner)
    assert len(calls) == 3

    def dirty(argv: Any, *, timeout: float | None = None) -> Any:
        result = runner(argv, timeout=timeout)
        return SUPERVISOR.CommandResult(0, " M private\n") if "status" in tuple(argv) else result

    with pytest.raises(SUPERVISOR.SupervisorError, match="source_dirty"):
        SUPERVISOR.validate_source(tmp_path, SOURCE_SHA, TREE_SHA, dirty)


def test_image_requires_id_and_both_revision_labels(tmp_path: Path) -> None:
    protocol, _, _ = _protocol_files(tmp_path)

    def runner(argv: Any, *, timeout: float | None = None) -> Any:
        del argv, timeout
        return SUPERVISOR.CommandResult(
            0,
            json.dumps(
                {
                    "Id": IMAGE_ID,
                    "Os": "linux",
                    "Architecture": "arm64",
                    "Config": {
                        "User": "10001:10001",
                        "Volumes": {destination: {} for destination in IMAGE_VOLUME_DESTINATIONS},
                        "Labels": {
                            "org.opencontainers.image.revision": SOURCE_SHA,
                            "io.incypher.rapido.source-revision": SOURCE_SHA,
                            "io.incypher.rapido.base-reference": "rapido@sha256:" + "b" * 64,
                        },
                    },
                }
            ),
        )

    assert SUPERVISOR.inspect_image(protocol, runner).image_id == IMAGE_ID

    def wrong(argv: Any, *, timeout: float | None = None) -> Any:
        value = json.loads(runner(argv, timeout=timeout).stdout)
        value["Config"]["Labels"]["org.opencontainers.image.revision"] = "4" * 40
        return SUPERVISOR.CommandResult(0, json.dumps(value))

    with pytest.raises(SUPERVISOR.SupervisorError, match="image_identity"):
        SUPERVISOR.inspect_image(protocol, wrong)

    def wrong_platform(argv: Any, *, timeout: float | None = None) -> Any:
        value = json.loads(runner(argv, timeout=timeout).stdout)
        value["Architecture"] = "amd64"
        return SUPERVISOR.CommandResult(0, json.dumps(value))

    with pytest.raises(SUPERVISOR.SupervisorError, match="image_identity"):
        SUPERVISOR.inspect_image(protocol, wrong_platform)

    def wrong_user(argv: Any, *, timeout: float | None = None) -> Any:
        value = json.loads(runner(argv, timeout=timeout).stdout)
        value["Config"]["User"] = "0:0"
        return SUPERVISOR.CommandResult(0, json.dumps(value))

    with pytest.raises(SUPERVISOR.SupervisorError, match="image_identity"):
        SUPERVISOR.inspect_image(protocol, wrong_user)

    def floating_base(argv: Any, *, timeout: float | None = None) -> Any:
        value = json.loads(runner(argv, timeout=timeout).stdout)
        value["Config"]["Labels"]["io.incypher.rapido.base-reference"] = "rapido:latest"
        return SUPERVISOR.CommandResult(0, json.dumps(value))

    with pytest.raises(SUPERVISOR.SupervisorError, match="image_identity"):
        SUPERVISOR.inspect_image(protocol, floating_base)

    def declared_volume_drift(argv: Any, *, timeout: float | None = None) -> Any:
        value = json.loads(runner(argv, timeout=timeout).stdout)
        value["Config"]["Volumes"]["/unexpected"] = {}
        return SUPERVISOR.CommandResult(0, json.dumps(value))

    with pytest.raises(SUPERVISOR.SupervisorError, match="image_identity"):
        SUPERVISOR.inspect_image(protocol, declared_volume_drift)


def test_image_source_probe_rejects_mismatched_base_and_always_removes(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)

    class SourceProbeFake:
        def __init__(
            self,
            *,
            mutation: str | None = None,
            remove_fails: bool = False,
            create_fails: bool = False,
            malformed_id: bool = False,
        ) -> None:
            self.mutation = mutation
            self.remove_fails = remove_fails
            self.create_fails = create_fails
            self.malformed_id = malformed_id
            self.existing = False
            self.labels: dict[str, str] = {}
            self.mounts: list[dict[str, object]] = []
            self.volumes: dict[str, dict[str, object]] = {}
            self.commands: list[tuple[str, ...]] = []

        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            del timeout
            command = tuple(argv)
            self.commands.append(command)
            if command[:3] == ("git", "-C", str(ROOT)) and "ls-files" in command:
                tracked = sorted(
                    path.relative_to(ROOT).as_posix() for path in (ROOT / "rapido").rglob("*.py")
                )
                return SUPERVISOR.CommandResult(0, "\0".join(tracked) + "\0")
            if command[:3] == ("docker", "ps", "--all"):
                value = PROBE_ID if "--quiet" in command else SUPERVISOR._SOURCE_PROBE_NAME
                return SUPERVISOR.CommandResult(
                    0,
                    f"{value}\n" if self.existing else "",
                )
            if command[:2] == ("docker", "create"):
                if self.create_fails:
                    return SUPERVISOR.CommandResult(1, "")
                self.existing = True
                for index, value in enumerate(command):
                    if value == "--label":
                        key, label_value = command[index + 1].split("=", 1)
                        self.labels[key] = label_value
                self.mounts = [
                    _anonymous_volume(destination, marker)
                    for destination, marker in zip(
                        IMAGE_VOLUME_DESTINATIONS, ("c", "d"), strict=True
                    )
                ]
                self.volumes = {
                    str(mount["Name"]): _volume_metadata(mount) for mount in self.mounts
                }
                return SUPERVISOR.CommandResult(
                    0,
                    "malformed\n" if self.malformed_id else f"{PROBE_ID}\n",
                )
            if command[:3] == ("docker", "container", "inspect"):
                return SUPERVISOR.CommandResult(
                    0,
                    json.dumps(
                        {
                            "Id": PROBE_ID,
                            "Name": f"/{SUPERVISOR._SOURCE_PROBE_NAME}",
                            "Image": IMAGE_ID,
                            "Config": {
                                "User": SUPERVISOR.CONTAINER_USER,
                                "Labels": self.labels,
                                "Volumes": {
                                    destination: {} for destination in IMAGE_VOLUME_DESTINATIONS
                                },
                            },
                            "State": {"Running": False},
                            "Mounts": self.mounts,
                        }
                    ),
                )
            if command[:3] == ("docker", "volume", "inspect"):
                names = command[3:]
                if any(name not in self.volumes for name in names):
                    return SUPERVISOR.CommandResult(1, "[]")
                return SUPERVISOR.CommandResult(
                    0,
                    json.dumps([self.volumes[name] for name in names]),
                )
            if command[:4] == ("docker", "volume", "ls", "--quiet"):
                expected = command[-1].removeprefix("name=^").removesuffix("$")
                return SUPERVISOR.CommandResult(
                    0,
                    f"{expected}\n" if expected in self.volumes else "",
                )
            if command[:2] == ("docker", "cp"):
                source = command[2]
                destination = Path(command[3])
                if source.endswith(SUPERVISOR._INSTALLED_RAPIDO):
                    destination.mkdir()
                    for source_path in (ROOT / "rapido").rglob("*.py"):
                        copied = destination / source_path.relative_to(ROOT / "rapido")
                        copied.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(source_path, copied)
                    target = min(destination.rglob("*.py"))
                    if self.mutation == "changed":
                        target.write_bytes(target.read_bytes() + b"\n# drift\n")
                    elif self.mutation == "missing":
                        target.unlink()
                    elif self.mutation in {"pyc", "so"}:
                        (destination / f"malicious.{self.mutation}").write_bytes(b"drift")
                else:
                    shutil.copy2(
                        ROOT / SUPERVISOR._WRAPPER_SOURCES[Path(source).name],
                        destination,
                    )
                return SUPERVISOR.CommandResult(0, "")
            if command[:3] == ("docker", "rm", "--volumes"):
                assert command[-1] == PROBE_ID
                if self.remove_fails:
                    return SUPERVISOR.CommandResult(1, "")
                self.volumes.clear()
                self.existing = False
                return SUPERVISOR.CommandResult(0, "")
            raise AssertionError(command)

    matching = SourceProbeFake()
    SUPERVISOR.verify_image_source(
        protocol,
        ROOT,
        paths.output,
        matching,
        clock=FakeClock(),
    )
    create = next(command for command in matching.commands if command[:2] == ("docker", "create"))
    assert create[create.index("--name") + 1] == SUPERVISOR._SOURCE_PROBE_NAME
    assert create[create.index("--network") + 1] == "none"
    assert "--mount" not in create and "--volume" not in create and "-v" not in create
    assert {mount["Destination"] for mount in matching.mounts} == set(IMAGE_VOLUME_DESTINATIONS)
    assert all(mount["Type"] == "volume" for mount in matching.mounts)
    assert not any(command[:2] == ("docker", "start") for command in matching.commands)
    assert all(
        command[2].startswith(f"{PROBE_ID}:")
        for command in matching.commands
        if command[:2] == ("docker", "cp")
    )
    assert matching.existing is False

    for mutation in ("changed", "missing", "pyc", "so"):
        mismatched = SourceProbeFake(mutation=mutation)
        with pytest.raises(SUPERVISOR.SupervisorError, match="image_source_mismatch"):
            SUPERVISOR.verify_image_source(
                protocol,
                ROOT,
                paths.output,
                mismatched,
                clock=FakeClock(),
            )
        assert mismatched.existing is False
        assert any(
            command == ("docker", "rm", "--volumes", PROBE_ID) for command in mismatched.commands
        )

    removal_failure = SourceProbeFake(remove_fails=True)
    with pytest.raises(SUPERVISOR.SupervisorError, match="image_source_probe_cleanup"):
        SUPERVISOR.verify_image_source(
            protocol,
            ROOT,
            paths.output,
            removal_failure,
            clock=FakeClock(),
        )

    for unsafe in (SourceProbeFake(create_fails=True),):
        with pytest.raises(
            SUPERVISOR.SupervisorError,
            match="image_source_probe_create|image_source_probe_identity",
        ):
            SUPERVISOR.verify_image_source(
                protocol,
                ROOT,
                paths.output,
                unsafe,
                clock=FakeClock(),
            )
        assert not any(command[:2] == ("docker", "rm") for command in unsafe.commands)
    reconciled = SourceProbeFake(malformed_id=True)
    SUPERVISOR.verify_image_source(protocol, ROOT, paths.output, reconciled, clock=FakeClock())
    assert reconciled.existing is False
    assert not any(path.name.startswith(".rapido-image-source-") for path in paths.output.iterdir())


def test_host_budget_enforces_registered_envelope() -> None:
    def runner(argv: Any, *, timeout: float | None = None) -> Any:
        del argv, timeout
        return SUPERVISOR.CommandResult(0, json.dumps({"NCPU": 14, "MemTotal": 24 * 1024**3}))

    SUPERVISOR.validate_host_budget(runner)

    def small(argv: Any, *, timeout: float | None = None) -> Any:
        del argv, timeout
        return SUPERVISOR.CommandResult(0, json.dumps({"NCPU": 11, "MemTotal": 24 * 1024**3}))

    with pytest.raises(SUPERVISOR.SupervisorError, match="host_budget_invalid"):
        SUPERVISOR.validate_host_budget(small)


def test_evaluation_common_barrier_receipts_resource_peaks_and_cleanup(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    runner = DockerFake(paths.output)
    clock = FakeClock()
    receipt = SUPERVISOR.run_evaluation(protocol, paths, runner=runner, clock=clock, finalize=False)

    assert receipt["status"] == "completed"
    starts = [command for command in runner.commands if command[:2] == ("docker", "start")]
    assert starts == [("docker", "start", H24_ID, SOAK_ID)]
    creates = [command for command in runner.commands if command[:2] == ("docker", "create")]
    barriers = {command[command.index("--start-at-unix-ms") + 1] for command in creates}
    assert len(barriers) == 1
    h24_mounts = runner.configs[H24_ID]["mounts"]
    soak_mounts = runner.configs[SOAK_ID]["mounts"]
    assert {mount["Destination"] for mount in h24_mounts if mount["Type"] == "volume"} == {"/state"}
    assert {mount["Destination"] for mount in soak_mounts if mount["Type"] == "volume"} == set(
        IMAGE_VOLUME_DESTINATIONS
    )
    assert any(
        mount["Type"] == "bind" and mount["Destination"] == "/auth/codex" for mount in h24_mounts
    )
    volume_inspects = [
        command for command in runner.commands if command[:3] == ("docker", "volume", "inspect")
    ]
    assert len(volume_inspects) == 2
    assert all(
        runner.commands.index(command) < runner.commands.index(starts[0])
        for command in volume_inspects
    )
    assert (
        receipt["barrier"]["global_deadline_wall_epoch_milliseconds"]
        - receipt["barrier"]["start_wall_epoch_milliseconds"]
        == 19_800_000
    )
    assert receipt["barrier"]["creation_before_barrier"] is True
    assert receipt["containers"]["h24"]["resources"] == {
        "samples": 1,
        "peak_cpu_percent": 125.5,
        "peak_rss_bytes": 256 * 1024**2,
        "peak_pids": 17,
        "oom_killed": False,
        "sample_interval_seconds": 0.0,
        "coverage_complete": True,
        "observation_status": "observed",
    }
    assert clock.monotonic() == 1_000 + 30 + 19_800 + SUPERVISOR.OWNER_QUIET_SECONDS
    assert not paths.work.exists()
    assert not paths.seed.exists()
    assert paths.auth.exists() and (paths.auth / "auth.json").exists()
    assert paths.output.exists() and (paths.output / SUPERVISOR.SUPERVISOR_RECEIPT).exists()
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths.output.iterdir())
    assert runner.volumes == {}
    assert any(command[:4] == ("docker", "volume", "ls", "--quiet") for command in runner.commands)


def test_evaluation_tracks_exact_ids_and_does_not_remove_name_replacements(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    replacements = {"8" * 64, "9" * 64}

    class ReplacementFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            if command == ("docker", "start", H24_ID, SOAK_ID):
                for original, replacement in zip(
                    (H24_ID, SOAK_ID), sorted(replacements), strict=True
                ):
                    expected_name = self.names[original]
                    self.names[original] = f"{expected_name}-renamed"
                    self.existing.add(replacement)
                    self.names[replacement] = expected_name
                    self.configs[replacement] = {
                        "labels": {},
                        "mounts": self.configs[original]["mounts"],
                    }
            return super().__call__(command, timeout=timeout)

    runner = ReplacementFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )

    assert receipt["status"] == "completed"
    assert receipt["cleanup"]["no_orphan_containers"] is True
    assert runner.existing == replacements
    removed = {
        command[-1] for command in runner.commands if command[:3] == ("docker", "rm", "--volumes")
    }
    assert removed == {H24_ID, SOAK_ID}


def test_timed_out_create_is_reconciled_by_private_label_and_exact_intent(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)

    class TimedOutCreateFake(DockerFake):
        timed_out = False

        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if command[:2] == ("docker", "create") and not self.timed_out:
                self.timed_out = True
                return SUPERVISOR.CommandResult(124)
            return result

    runner = TimedOutCreateFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )

    assert receipt["status"] == "completed"
    assert runner.existing == set()
    assert ("docker", "start", H24_ID, SOAK_ID) in runner.commands
    assert ("docker", "rm", "--volumes", H24_ID) in runner.commands


def test_timed_out_create_polls_for_delayed_daemon_visibility(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)

    class DelayedVisibilityFake(DockerFake):
        timed_out = False
        owner_inventories = 0

        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if command[:2] == ("docker", "create") and not self.timed_out:
                self.timed_out = True
                return SUPERVISOR.CommandResult(124)
            if self.timed_out and any(
                value.startswith(f"label={SUPERVISOR._OWNER_LABEL}=") for value in command
            ):
                self.owner_inventories += 1
                if self.owner_inventories == 1:
                    return SUPERVISOR.CommandResult(0, "")
            return result

    clock = FakeClock()
    runner = DelayedVisibilityFake(paths.output, clock=clock)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=clock,
        finalize=False,
    )

    assert receipt["status"] == "completed"
    assert runner.owner_inventories >= 2
    assert runner.existing == set()


def test_unresolved_create_polls_full_cleanup_bound_without_clean_attestation(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    clock = FakeClock()

    class VeryDelayedVisibilityFake(DockerFake):
        timed_out = False
        visible_at: float | None = None

        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if command[:2] == ("docker", "create") and not self.timed_out:
                self.timed_out = True
                self.visible_at = clock.monotonic() + 7
                return SUPERVISOR.CommandResult(124)
            if (
                self.visible_at is not None
                and clock.monotonic() < self.visible_at
                and any(value.startswith(f"label={SUPERVISOR._OWNER_LABEL}=") for value in command)
            ):
                return SUPERVISOR.CommandResult(0, "")
            return result

    runner = VeryDelayedVisibilityFake(paths.output, clock=clock)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=clock,
        finalize=False,
    )

    assert runner.visible_at == 1_007
    assert clock.monotonic() == 1_015
    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "container_create"
    assert receipt["cleanup"]["containers_absent"] is False
    assert receipt["cleanup"]["no_orphan_containers"] is False
    assert not any(command[:2] == ("docker", "start") for command in runner.commands)
    assert runner.existing == set()
    assert ("docker", "rm", "--volumes", H24_ID) in runner.commands


def test_create_intent_inspection_cannot_extend_barrier_deadline(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    protocol = replace(protocol, barrier_delay_seconds=1)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    clock = FakeClock()

    class SlowInspectFake(DockerFake):
        inspect_timeout: float | None = None

        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            if (
                command[:3] == ("docker", "container", "inspect")
                and command[3] == "--format={{json .}}"
            ):
                self.inspect_timeout = timeout
                assert timeout is not None
                clock.sleep(timeout)
            return super().__call__(command, timeout=timeout)

    runner = SlowInspectFake(paths.output, clock=clock)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=clock,
        finalize=False,
    )

    assert runner.inspect_timeout == pytest.approx(1.0)
    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "container_create"
    assert not any(command[:2] == ("docker", "start") for command in runner.commands)
    assert runner.existing == set()


def test_ambiguous_owned_create_fails_closed_and_cleans_every_exact_id(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    second_id = "a" * 64

    class AmbiguousCreateFake(DockerFake):
        injected = False

        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if command[:2] == ("docker", "create") and not self.injected:
                self.injected = True
                self.existing.add(second_id)
                self.names[second_id] = self.names[H24_ID]
                self.configs[second_id] = self.configs[H24_ID]
            return result

    runner = AmbiguousCreateFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "container_create_ambiguous"
    assert not any(command[:2] == ("docker", "start") for command in runner.commands)
    assert runner.existing == set()
    removed = {
        command[-1] for command in runner.commands if command[:3] == ("docker", "rm", "--volumes")
    }
    assert removed == {H24_ID, second_id}


def test_late_same_label_replacement_is_removed_and_fails_closed(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    late_id = "c" * 64

    class LateReplacementFake(DockerFake):
        injected = False

        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if command == ("docker", "rm", "--volumes", H24_ID) and not self.injected:
                self.injected = True
                self.existing.add(late_id)
                self.names[late_id] = SUPERVISOR._H24_NAME
                self.configs[late_id] = self.configs[H24_ID]
            return result

    clock = FakeClock()
    runner = LateReplacementFake(paths.output, clock=clock)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=clock,
        finalize=False,
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "container_ownership_ambiguous"
    assert runner.existing == set()
    assert ("docker", "rm", "--volumes", late_id) in runner.commands


def test_reconciled_create_rejects_mount_drift_before_start_and_cleans_exact_id(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)

    class MountDriftFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if (
                command[:3] == ("docker", "container", "inspect")
                and command[3] == "--format={{json .}}"
                and command[-1] == H24_ID
            ):
                value = json.loads(result.stdout)
                value["Mounts"][0]["Source"] = "/unexpected"
                return SUPERVISOR.CommandResult(0, json.dumps(value))
            return result

    runner = MountDriftFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "container_identity"
    assert not any(command[:2] == ("docker", "start") for command in runner.commands)
    assert runner.existing == set()


@pytest.mark.parametrize(
    "mutation",
    (
        "extra",
        "duplicate",
        "type",
        "destination",
        "name",
        "source",
        "driver",
        "mode",
        "rw",
        "propagation",
        "declared",
    ),
)
def test_reconciled_create_rejects_anonymous_volume_drift(tmp_path: Path, mutation: str) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)

    class VolumeDriftFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if (
                command[:3] == ("docker", "container", "inspect")
                and command[3] == "--format={{json .}}"
                and command[-1] == H24_ID
            ):
                value = json.loads(result.stdout)
                volume = next(
                    mount
                    for mount in value["Mounts"]
                    if mount["Type"] == "volume" and mount["Destination"] == "/state"
                )
                if mutation == "extra":
                    value["Mounts"].append(_anonymous_volume("/unexpected", "e"))
                elif mutation == "duplicate":
                    duplicate = _anonymous_volume("/state", "e")
                    value["Mounts"].append(duplicate)
                elif mutation == "type":
                    volume["Type"] = "tmpfs"
                elif mutation == "destination":
                    volume["Destination"] = "/unexpected"
                elif mutation == "name":
                    volume["Name"] = "short"
                elif mutation == "source":
                    volume["Source"] = "/var/lib/docker/volumes/unexpected/_data"
                elif mutation == "driver":
                    volume["Driver"] = "unexpected"
                elif mutation == "mode":
                    volume["Mode"] = "z"
                elif mutation == "rw":
                    volume["RW"] = False
                elif mutation == "propagation":
                    volume["Propagation"] = "rprivate"
                else:
                    value["Config"]["Volumes"]["/unexpected"] = {}
                return SUPERVISOR.CommandResult(0, json.dumps(value))
            return result

    runner = VolumeDriftFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "container_identity"
    assert not any(command[:2] == ("docker", "start") for command in runner.commands)
    assert runner.existing == set()


def test_anonymous_volume_accepts_custom_docker_data_root(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)

    class CustomRootFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if (
                command[:3] == ("docker", "container", "inspect")
                and command[3] == "--format={{json .}}"
            ):
                value = json.loads(result.stdout)
                for mount in value["Mounts"]:
                    if mount["Type"] != "volume":
                        continue
                    name = mount["Name"]
                    source = f"/custom/docker-data/volumes/{name}/data"
                    mount["Source"] = source
                    self.volumes[name]["Mountpoint"] = source
                return SUPERVISOR.CommandResult(0, json.dumps(value))
            return result

    runner = CustomRootFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )

    assert receipt["status"] == "completed"
    assert runner.volumes == {}


def test_named_hex_volume_is_rejected_and_retention_blocks_cleanup_attestation(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)

    class NamedVolumeFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if command[:2] == ("docker", "create"):
                container_id = result.stdout.strip()
                for mount in self.configs[container_id]["mounts"]:
                    if mount["Type"] == "volume":
                        self.volumes[str(mount["Name"])]["Labels"] = {}
            return result

    runner = NamedVolumeFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "container_identity"
    assert receipt["cleanup"]["containers_absent"] is False
    assert receipt["cleanup"]["no_orphan_containers"] is False
    assert runner.existing == set()
    assert runner.volumes


@pytest.mark.parametrize(
    "mutation",
    ("created_at", "driver", "labels", "mountpoint", "name", "options", "scope", "extra"),
)
def test_anonymous_volume_metadata_drift_fails_before_start(tmp_path: Path, mutation: str) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)

    class MetadataDriftFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if command[:3] == ("docker", "volume", "inspect") and result.returncode == 0:
                value = json.loads(result.stdout)
                metadata = value[0]
                if mutation == "created_at":
                    metadata["CreatedAt"] = "2026-09-19T19:57:14"
                elif mutation == "driver":
                    metadata["Driver"] = "unexpected"
                elif mutation == "labels":
                    metadata["Labels"] = {"com.docker.volume.anonymous": "true"}
                elif mutation == "mountpoint":
                    metadata["Mountpoint"] = "/unexpected"
                elif mutation == "name":
                    metadata["Name"] = "unexpected"
                elif mutation == "options":
                    metadata["Options"] = {}
                elif mutation == "scope":
                    metadata["Scope"] = "global"
                else:
                    metadata["Unexpected"] = True
                return SUPERVISOR.CommandResult(0, json.dumps(value))
            return result

    runner = MetadataDriftFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "container_identity"
    assert not any(command[:2] == ("docker", "start") for command in runner.commands)
    assert runner.existing == set()
    assert runner.volumes == {}


def test_volume_inventory_error_blocks_clean_attestation(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)

    class InventoryErrorFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            if command[:4] == ("docker", "volume", "ls", "--quiet"):
                self.commands.append(command)
                return SUPERVISOR.CommandResult(1, "")
            return super().__call__(command, timeout=timeout)

    runner = InventoryErrorFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "cleanup_incomplete"
    assert receipt["cleanup"]["containers_absent"] is False
    assert receipt["cleanup"]["no_orphan_containers"] is False
    assert runner.volumes == {}


def test_unavailable_intent_inspect_blocks_clean_attestation_without_volume_names(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)

    class InspectFailureFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if (
                command[:3] == ("docker", "container", "inspect")
                and command[3] == "--format={{json .}}"
            ):
                return SUPERVISOR.CommandResult(1, "")
            return result

    runner = InspectFailureFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "container_identity"
    assert receipt["cleanup"]["containers_absent"] is False
    assert receipt["cleanup"]["no_orphan_containers"] is False
    assert runner.existing == set()
    assert runner.volumes == {}
    assert not any(
        command[:4] == ("docker", "volume", "ls", "--quiet") for command in runner.commands
    )


def test_extra_key_mount_harvests_name_and_retention_blocks_cleanup(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)

    class ExtraKeyRetainedFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if command[:2] == ("docker", "create"):
                container_id = result.stdout.strip()
                for mount in self.configs[container_id]["mounts"]:
                    if mount["Type"] == "volume":
                        self.volumes[str(mount["Name"])]["Labels"] = {}
            if (
                command[:3] == ("docker", "container", "inspect")
                and command[3] == "--format={{json .}}"
            ):
                value = json.loads(result.stdout)
                volume = next(mount for mount in value["Mounts"] if mount["Type"] == "volume")
                volume["Unexpected"] = True
                return SUPERVISOR.CommandResult(0, json.dumps(value))
            return result

    runner = ExtraKeyRetainedFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "container_identity"
    assert receipt["cleanup"]["containers_absent"] is False
    assert receipt["cleanup"]["no_orphan_containers"] is False
    assert runner.existing == set()
    assert runner.volumes
    queries = [
        command
        for command in runner.commands
        if command[:4] == ("docker", "volume", "ls", "--quiet")
    ]
    assert {command[-1] for command in queries} == {f"name=^{name}$" for name in runner.volumes}


def test_later_volume_intent_success_does_not_clear_prior_unresolved_state(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    clock = FakeClock()
    runner = DockerFake(paths.output, clock=clock)
    ownership_token = "e" * 64
    prior_id = "f" * 64
    state = SUPERVISOR.EvaluationState(unresolved_volume_intents={prior_id})
    intent = SUPERVISOR.ContainerIntent(
        protocol.h24_name,
        "h24",
        protocol.image_id,
        (
            (paths.auth, "/auth/codex", False),
            (paths.work, "/work", False),
            (paths.output, "/output", False),
            (paths.seed, "/seed/oracle.key", True),
            (paths.preregistration, "/run/rapido-protocol/preregistration.json", True),
        ),
    )

    container_id = SUPERVISOR._create_owned_container(
        SUPERVISOR.h24_create_argv(protocol, paths, ownership_token=ownership_token),
        intent,
        ownership_token,
        runner,
        state,
        failure="container_create",
        clock=clock,
        deadline=clock.monotonic() + 30,
    )

    assert container_id == H24_ID
    assert state.unresolved_volume_intents == {prior_id}
    assert (
        SUPERVISOR._cleanup_owned_containers(
            ownership_token,
            state,
            runner,
            clock,
            clock.monotonic() + SUPERVISOR.OWNER_CLEANUP_SECONDS,
        )
        is False
    )
    assert runner.existing == set()
    assert runner.volumes == {}


def test_auth_integrity_rejects_structural_corruption_but_allows_safe_rotation(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)

    def execute(root: Path, mutation: str) -> dict[str, object]:
        paths = _paths(root, preregistration, registration)
        _seed_child_receipts(paths.output, protocol)

        class AuthMutationFake(DockerFake):
            mutated = False

            def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
                command = tuple(argv)
                if command[:2] == ("docker", "start") and not self.mutated:
                    self.mutated = True
                    auth_file = paths.auth / "auth.json"
                    if mutation == "symlink":
                        replacement = paths.auth / "replacement.json"
                        replacement.write_text('{"tokens":{},"refreshed":true}')
                        replacement.chmod(0o600)
                        auth_file.unlink()
                        auth_file.symlink_to(replacement)
                    elif mutation == "mode":
                        auth_file.chmod(0o644)
                    elif mutation == "hardlink":
                        os.link(auth_file, paths.auth / "second-link.json")
                    elif mutation == "invalid_json":
                        auth_file.write_text("{")
                    elif mutation == "key_loss":
                        auth_file.write_text('{"refreshed":true}')
                    elif mutation == "capability":
                        (paths.auth / "config.toml").write_text("enabled = true")
                    else:
                        replacement = paths.auth / "replacement.json"
                        replacement.write_text('{"tokens":{},"refreshed":true}')
                        replacement.chmod(0o600)
                        os.replace(replacement, auth_file)
                return super().__call__(command, timeout=timeout)

        return SUPERVISOR.run_evaluation(
            protocol,
            paths,
            runner=AuthMutationFake(paths.output),
            clock=FakeClock(),
            finalize=False,
        )

    for mutation in ("symlink", "mode", "hardlink", "invalid_json", "key_loss", "capability"):
        corrupt_root = tmp_path / mutation
        corrupt_root.mkdir()
        corrupted = execute(corrupt_root, mutation)
        assert corrupted["status"] == "failed"
        assert corrupted["failure_class"] == "auth_integrity"
        assert corrupted["cleanup"]["auth_preserved"] is False

    rotation_root = tmp_path / "rotation"
    rotation_root.mkdir()
    rotated = execute(rotation_root, "rotation")
    assert rotated["status"] == "completed"
    assert rotated["cleanup"]["auth_preserved"] is True


def test_resource_cadence_uses_measured_gap_and_terminal_coverage(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    protocol = replace(protocol, scoring_seconds=20, barrier_delay_seconds=1)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=DockerFake(paths.output, keep_h24_running=True, keep_soak_running=True),
        clock=FakeClock(),
        finalize=False,
    )

    resources = receipt["containers"]["h24"]["resources"]
    maximum = protocol.preregistration["runtime_resource_limits"]["sampling_interval_seconds_max"]
    assert resources["observation_status"] == "observed"
    assert resources["coverage_complete"] is True
    assert resources["sample_interval_seconds"] == 5.0
    assert resources["sample_interval_seconds"] <= maximum

    early_root = tmp_path / "early"
    early_root.mkdir()
    early_paths = _paths(early_root, preregistration, registration)
    _seed_child_receipts(early_paths.output, protocol)
    early = SUPERVISOR.run_evaluation(
        protocol,
        early_paths,
        runner=DockerFake(early_paths.output),
        clock=FakeClock(),
        finalize=False,
    )
    early_resources = early["containers"]["h24"]["resources"]
    assert early_resources["observation_status"] == "observed"
    assert early_resources["coverage_complete"] is True
    assert early_resources["sample_interval_seconds"] == 0.0


def test_slow_stats_records_over_max_gap_instead_of_nominal_cadence(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    protocol = replace(protocol, scoring_seconds=30, barrier_delay_seconds=1)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    clock = FakeClock()

    class SlowStats(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            if tuple(argv)[:2] == ("docker", "stats"):
                clock.sleep(12)
            return super().__call__(argv, timeout=timeout)

    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=SlowStats(
            paths.output,
            keep_h24_running=True,
            keep_soak_running=True,
            clock=clock,
        ),
        clock=clock,
        finalize=False,
    )

    resources = receipt["containers"]["h24"]["resources"]
    maximum = protocol.preregistration["runtime_resource_limits"]["sampling_interval_seconds_max"]
    assert resources["observation_status"] == "observed"
    assert resources["sample_interval_seconds"] >= 12
    assert resources["sample_interval_seconds"] > maximum


def test_deadline_stops_only_running_exact_container_without_filler(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    protocol = replace(protocol, scoring_seconds=2, barrier_delay_seconds=1)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    clock = FakeClock()
    runner = DockerFake(paths.output, keep_soak_running=True, clock=clock)
    SUPERVISOR.run_evaluation(protocol, paths, runner=runner, clock=clock, finalize=False)

    scoring_stops = [
        (command, timestamp)
        for command, timestamp in runner.command_times
        if command[:4] == ("docker", "stop", "--time", "0")
    ]
    assert scoring_stops == [(("docker", "stop", "--time", "0", SOAK_ID), 1_183.0)]
    assert not any(
        command[:4] == ("docker", "stop", "--time", "190") for command in runner.commands
    )
    assert (
        sum(
            any("offline_oracle_pilot.py" in argument for argument in command)
            for command in runner.commands
        )
        == 1
    )


def test_late_sampling_consumes_registered_cleanup_grace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    clock = FakeClock()
    offsets: list[int] = []
    blocking_calls: list[tuple[tuple[str, ...], float, float]] = []

    class SlowDockerFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            if (
                command[:2] in {("docker", "stats"), ("docker", "stop"), ("docker", "logs")}
                or command[:3] == ("docker", "container", "inspect")
                or command[:2] == ("docker", "rm")
            ):
                assert timeout is not None and timeout > 0
                blocking_calls.append((command, clock.monotonic(), timeout))
            if command[:2] == ("docker", "stats") or (
                command[:3] == ("docker", "container", "inspect")
                and command[3] == "--format={{json .State}}"
            ):
                clock.sleep(30)
            return super().__call__(command, timeout=timeout)

    def finalize(*args: object, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        del args
        offsets.append(int(kwargs["cleanup_started_offset_milliseconds"]))
        for name, schema in (
            (SUPERVISOR.FINAL_RECEIPT, SUPERVISOR.EVALUATION_RECEIPT_SCHEMA),
            (SUPERVISOR.EVALUATION_RESULT, "rapido-offline-h24-evaluation-v1"),
        ):
            path = paths.output / name
            path.write_text(json.dumps({"schema": schema}))
            path.chmod(0o600)
        return {}, {}

    monkeypatch.setattr(SUPERVISOR, "finalize_evaluation", finalize)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=SlowDockerFake(paths.output, keep_soak_running=True, clock=clock),
        clock=clock,
    )

    registered_outer_deadline = 1_000 + 30 + 19_800 + 190
    scoring_deadline = 1_000 + 30 + 19_800
    worker_drain_deadline = scoring_deadline + 180
    assert clock.monotonic() >= registered_outer_deadline
    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "cleanup_timeout"
    assert offsets and set(offsets) == {19_800_000}
    assert blocking_calls
    for command, started, timeout in blocking_calls:
        if command[:2] == ("docker", "stats") or started < scoring_deadline:
            deadline = scoring_deadline
        elif command[:3] == ("docker", "container", "inspect") and started < worker_drain_deadline:
            deadline = worker_drain_deadline
        else:
            deadline = registered_outer_deadline
        assert started + timeout <= deadline
    assert any(timeout < 30 for _, _, timeout in blocking_calls)


def test_oom_and_child_failures_are_retained_not_dropped(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    runner = DockerFake(paths.output, oom=True)
    receipt = SUPERVISOR.run_evaluation(
        protocol, paths, runner=runner, clock=FakeClock(), finalize=False
    )
    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "container_oom"
    assert receipt["containers"]["h24"]["resources"]["oom_killed"] is True
    assert (paths.output / "h24.docker.log").read_text() == "private raw child log\n"


def test_public_receipt_excludes_paths_ids_raw_logs_and_secrets(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    runner = DockerFake(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=runner,
        clock=FakeClock(),
        finalize=False,
    )
    encoded = json.dumps(receipt, sort_keys=True)
    assert str(tmp_path) not in encoded
    assert "private raw child log" not in encoded
    assert "candidate-value" not in encoded
    assert "CTFD_API_TOKEN" not in encoded
    assert "container_id" not in encoded
    assert H24_ID not in encoded and SOAK_ID not in encoded
    owner_labels = {
        value.split("=", 1)[1]
        for command in runner.commands
        for value in command
        if value.startswith(f"{SUPERVISOR._OWNER_LABEL}=")
    }
    assert owner_labels and all(value not in encoded for value in owner_labels)
    assert SOURCE_SHA in encoded and IMAGE_ID in encoded


def test_stats_parser_retains_nulls_instead_of_inventing_values() -> None:
    peak = SUPERVISOR.ResourcePeak()
    peak.observe({"CPUPerc": "n/a", "MemUsage": "n/a", "PIDs": "n/a"})
    assert peak.public() == {
        "samples": 1,
        "peak_cpu_percent": None,
        "peak_rss_bytes": None,
        "peak_pids": None,
        "oom_killed": None,
        "sample_interval_seconds": None,
        "coverage_complete": False,
        "observation_status": "unavailable",
    }
    assert SUPERVISOR._runtime_resources(peak)["observation_status"] == "unavailable"

    incomplete = SUPERVISOR.ResourcePeak(100.0, 1024, 4, False, 1)
    assert SUPERVISOR._runtime_resources(incomplete) == {
        "observation_status": "partial",
        "sample_interval_seconds": None,
        "peak_cpu_percent": 100.0,
        "peak_rss_bytes": 1024,
        "peak_pids": 4,
        "oom_killed": False,
    }


def test_descriptor_preflight_emits_only_frozen_closed_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)

    class DescriptorFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            if command[:4] == ("docker", "start", "--attach", DESCRIPTOR_ID):
                self.commands.append(command)
                _seed_descriptor_receipt(paths.output, protocol)
                return SUPERVISOR.CommandResult(0, "")
            return super().__call__(command, timeout=timeout)

    runner = DescriptorFake(paths.output)
    result = SUPERVISOR.run_descriptor_preflight(protocol, paths, runner=runner, clock=FakeClock())
    assert result == {
        "schema": SUPERVISOR.DESCRIPTOR_SCHEMA,
        "protocol_id": SUPERVISOR.PREREGISTRATION_SCHEMA,
        "status": "matched",
        "descriptors": protocol.preregistration["descriptor_preflight"],
    }
    encoded_commands = json.dumps(result)
    assert "source" not in encoded_commands
    assert "image" not in encoded_commands
    assert "oracle" not in encoded_commands
    mounts = runner.configs[DESCRIPTOR_ID]["mounts"]
    assert {mount["Destination"] for mount in mounts if mount["Type"] == "volume"} == {"/state"}
    assert any(
        mount["Type"] == "bind" and mount["Destination"] == "/auth/codex" for mount in mounts
    )


@pytest.mark.parametrize(
    "binding",
    ("preregistration", "source", "image", "descriptors"),
)
def test_execute_rejects_unbound_descriptor_receipt_before_docker_create(
    tmp_path: Path,
    binding: str,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    descriptor_path = paths.output / SUPERVISOR.DESCRIPTOR_RECEIPT
    descriptor = json.loads(descriptor_path.read_text())
    if binding == "preregistration":
        descriptor["preregistration_sha256"] = "f" * 64
    elif binding == "source":
        descriptor["source"]["observed"]["head_sha"] = "f" * 40
    elif binding == "image":
        descriptor["image"]["observed"]["id"] = "sha256:" + "f" * 64
    else:
        descriptor["descriptors"][0]["returned_effort"] = "low"
    descriptor_path.write_text(json.dumps(descriptor))

    def no_docker(argv: Any, *, timeout: float | None = None) -> Any:
        del argv, timeout
        raise AssertionError("descriptor binding must fail before Docker access")

    with pytest.raises(SUPERVISOR.SupervisorError, match="preflight_receipt"):
        SUPERVISOR.run_evaluation(
            protocol,
            paths,
            runner=no_docker,
            clock=FakeClock(),
            finalize=False,
        )


def test_descriptor_preflight_reconciles_timed_out_create_and_removes_exact_id(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)

    class DescriptorTimeoutFake(DockerFake):
        timed_out = False

        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            if command == ("docker", "start", "--attach", DESCRIPTOR_ID):
                self.commands.append(command)
                _seed_descriptor_receipt(paths.output, protocol)
                return SUPERVISOR.CommandResult(0, "")
            result = super().__call__(command, timeout=timeout)
            if command[:2] == ("docker", "create") and not self.timed_out:
                self.timed_out = True
                return SUPERVISOR.CommandResult(124)
            return result

    runner = DescriptorTimeoutFake(paths.output)
    result = SUPERVISOR.run_descriptor_preflight(protocol, paths, runner=runner, clock=FakeClock())

    assert result["status"] == "matched"
    assert runner.existing == set()
    assert ("docker", "rm", "--volumes", DESCRIPTOR_ID) in runner.commands


def test_descriptor_preflight_rejects_ambiguous_create_and_cleans_all_owned_ids(
    tmp_path: Path,
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    second_id = "b" * 64

    class DescriptorAmbiguousFake(DockerFake):
        injected = False

        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            result = super().__call__(command, timeout=timeout)
            if command[:2] == ("docker", "create") and not self.injected:
                self.injected = True
                self.existing.add(second_id)
                self.names[second_id] = self.names[DESCRIPTOR_ID]
                self.configs[second_id] = self.configs[DESCRIPTOR_ID]
            return result

    runner = DescriptorAmbiguousFake(paths.output)
    with pytest.raises(SUPERVISOR.SupervisorError, match="preflight_create_ambiguous"):
        SUPERVISOR.run_descriptor_preflight(protocol, paths, runner=runner, clock=FakeClock())

    assert runner.existing == set()
    assert not any(command[:2] == ("docker", "start") for command in runner.commands)
    removed = {
        command[-1] for command in runner.commands if command[:3] == ("docker", "rm", "--volumes")
    }
    assert removed == {DESCRIPTOR_ID, second_id}


def test_finalizer_joins_sanitized_facts_and_writes_private_evaluation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    raw_h24 = paths.output / SUPERVISOR.H24_RECEIPT
    raw_h24.write_text(json.dumps({"schema": "rapido-offline-h24-pilot-v1"}))
    raw_h24.chmod(0o600)
    soak = paths.output / SUPERVISOR.SOAK_RECEIPT
    soak.write_text(
        json.dumps(
            {
                "schema": "rapido-benign-board-contract-v1",
                "scenarios": [
                    {
                        "scenario_id": "deadline_cancel_cleanup",
                        "facts": {
                            "owned_instances": 0,
                            "pending_writes": 0,
                            "workspace_entries": 0,
                        },
                    }
                ],
            }
        )
    )
    soak.chmod(0o600)
    paths.work.rmdir()
    calls: list[dict[str, object]] = []

    def build(**kwargs: object) -> dict[str, object]:
        calls.append(dict(kwargs))
        return {"schema": SUPERVISOR.EVALUATION_RECEIPT_SCHEMA}

    monkeypatch.setattr(SUPERVISOR, "build_evaluation_receipt", build)
    monkeypatch.setattr(
        SUPERVISOR,
        "evaluate_h24_receipt",
        lambda *_: {"schema": "rapido-offline-h24-evaluation-v1", "decision": "inconclusive"},
    )
    peak = SUPERVISOR.ResourcePeak(100.0, 1024, 4, False, 2)
    peak.start_coverage(0)
    peak.observe({}, 0)
    peak.end_coverage(10)
    final, evaluation = SUPERVISOR.finalize_evaluation(
        protocol,
        paths,
        barrier={
            "start_wall_epoch_milliseconds": 2_000_000_000_000,
            "global_deadline_wall_epoch_milliseconds": 2_000_019_800_000,
            "creation_before_barrier": True,
        },
        h24_peak=peak,
        cleanup_started_offset_milliseconds=19_800_000,
        cleanup_elapsed_milliseconds=1_000,
        containers_absent=True,
        cleanup_completed=True,
        workspace_residue_bytes=0,
    )
    assert len(calls) == 2
    assert calls[-1]["runtime_resources"] == {
        "observation_status": "observed",
        "sample_interval_seconds": 10.0,
        "peak_cpu_percent": 100.0,
        "peak_rss_bytes": 1024,
        "peak_pids": 4,
        "oom_killed": False,
    }
    assert calls[-1]["cleanup"]["privacy_scan_passed"] is True
    assert final["schema"] == SUPERVISOR.EVALUATION_RECEIPT_SCHEMA
    assert evaluation["decision"] == "inconclusive"
    for name in (SUPERVISOR.FINAL_RECEIPT, SUPERVISOR.EVALUATION_RESULT):
        assert stat.S_IMODE((paths.output / name).stat().st_mode) == 0o600


def test_cleanup_span_includes_private_deletion_and_first_persistence_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    protocol = replace(protocol, scoring_seconds=2, barrier_delay_seconds=1)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    clock = FakeClock()
    observed: list[int] = []
    private_inputs_present: list[tuple[bool, bool]] = []

    def finalize(*args: object, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        del args
        observed.append(int(kwargs["cleanup_elapsed_milliseconds"]))
        private_inputs_present.append((paths.work.exists(), paths.seed.exists()))
        clock.sleep(5)
        for name, schema in (
            (SUPERVISOR.FINAL_RECEIPT, SUPERVISOR.EVALUATION_RECEIPT_SCHEMA),
            (SUPERVISOR.EVALUATION_RESULT, "rapido-offline-h24-evaluation-v1"),
        ):
            path = paths.output / name
            path.write_text(json.dumps({"schema": schema}))
            path.chmod(0o600)
        return {}, {}

    monkeypatch.setattr(SUPERVISOR, "finalize_evaluation", finalize)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=DockerFake(paths.output),
        clock=clock,
    )
    assert observed == [1_000, 6_000, 11_000]
    assert private_inputs_present == [(True, True), (False, False), (False, False)]
    assert receipt["status"] == "completed"


def test_assembly_failure_preserves_private_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    protocol = replace(protocol, scoring_seconds=2, barrier_delay_seconds=1)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)

    def reject(*args: object, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        del args, kwargs
        raise SUPERVISOR.SupervisorError("privacy_scan")

    monkeypatch.setattr(SUPERVISOR, "finalize_evaluation", reject)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=DockerFake(paths.output),
        clock=FakeClock(),
    )

    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "privacy_scan"
    assert paths.work.exists()
    assert paths.seed.exists()
    assert not (paths.output / SUPERVISOR.FINAL_RECEIPT).exists()
    assert not (paths.output / SUPERVISOR.EVALUATION_RESULT).exists()


def test_late_persistence_records_failed_cleanup_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    protocol = replace(protocol, scoring_seconds=2, barrier_delay_seconds=1)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    clock = FakeClock()
    observed: list[int] = []

    def finalize(*args: object, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        del args
        observed.append(int(kwargs["cleanup_elapsed_milliseconds"]))
        clock.sleep(4)
        for name, schema in (
            (SUPERVISOR.FINAL_RECEIPT, SUPERVISOR.EVALUATION_RECEIPT_SCHEMA),
            (SUPERVISOR.EVALUATION_RESULT, "rapido-offline-h24-evaluation-v1"),
        ):
            path = paths.output / name
            path.write_text(json.dumps({"schema": schema}))
            path.chmod(0o600)
        return {}, {}

    monkeypatch.setattr(SUPERVISOR, "finalize_evaluation", finalize)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=DockerFake(paths.output, keep_soak_running=True),
        clock=clock,
    )

    assert observed == [181_000, 185_000, 189_000, 193_000]
    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "cleanup_timeout"


def test_worker_drain_leaves_tail_inside_outer_cleanup_grace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    protocol = replace(protocol, scoring_seconds=2, barrier_delay_seconds=1)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output, protocol)
    clock = FakeClock()
    observed: list[int] = []

    def finalize(*args: object, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        del args
        observed.append(int(kwargs["cleanup_elapsed_milliseconds"]))
        clock.sleep((3, 3, 3)[len(observed) - 1])
        for name, schema in (
            (SUPERVISOR.FINAL_RECEIPT, SUPERVISOR.EVALUATION_RECEIPT_SCHEMA),
            (SUPERVISOR.EVALUATION_RESULT, "rapido-offline-h24-evaluation-v1"),
        ):
            path = paths.output / name
            path.write_text(json.dumps({"schema": schema}))
            path.chmod(0o600)
        return {}, {}

    monkeypatch.setattr(SUPERVISOR, "finalize_evaluation", finalize)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=DockerFake(paths.output, keep_soak_running=True),
        clock=clock,
    )

    assert observed == [181_000, 184_000, 187_000]
    assert clock.monotonic() == 1_000 + 1 + 2 + 190
    assert receipt["status"] == "completed"
    assert receipt["protocol"]["worker_drain_seconds"] == 180
    assert receipt["protocol"]["cleanup_grace_seconds"] == 190


def test_no_shell_true_and_only_exact_container_removal() -> None:
    source = (ROOT / "scripts" / "offline_h24_supervisor.py").read_text()
    assert "shell=True" not in source
    assert "docker system prune" not in source
    assert "docker container prune" not in source
    assert "docker volume prune" not in source
