"""Secret-free tests for the sealed H24 Docker supervisor."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from dataclasses import replace
from pathlib import Path
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
    _private_file(auth / "auth.json", b"{}")
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
        oom: bool = False,
        clock: FakeClock | None = None,
    ) -> None:
        self.output = output
        self.keep_soak_running = keep_soak_running
        self.oom = oom
        self.clock = clock
        self.commands: list[tuple[str, ...]] = []
        self.command_times: list[tuple[tuple[str, ...], float]] = []
        self.existing: set[str] = set()
        self.running: set[str] = set()

    def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
        del timeout
        command = tuple(argv)
        self.commands.append(command)
        self.command_times.append((command, self.clock.monotonic() if self.clock else -1.0))
        if command[:3] == ("docker", "ps", "--all") and "--quiet" not in command:
            name = command[command.index("--filter") + 1].removeprefix("name=^/").removesuffix("$")
            return SUPERVISOR.CommandResult(0, f"{name}\n" if name in self.existing else "")
        if command == ("docker", "ps", "--all", "--quiet"):
            return SUPERVISOR.CommandResult(0, "")
        if command[:2] == ("docker", "create"):
            name = command[command.index("--name") + 1]
            self.existing.add(name)
            return SUPERVISOR.CommandResult(0, "created\n")
        if command[:2] == ("docker", "start") and "--attach" not in command:
            self.running.update(command[2:])
            return SUPERVISOR.CommandResult(0, "started\n")
        if command[:2] == ("docker", "stats"):
            rows = [
                json.dumps(
                    {
                        "Name": name,
                        "CPUPerc": "125.5%",
                        "MemUsage": "256MiB / 20GiB",
                        "PIDs": "17",
                    }
                )
                for name in command[4:]
            ]
            return SUPERVISOR.CommandResult(0, "\n".join(rows))
        if command[:3] == ("docker", "container", "inspect"):
            name = command[-1]
            running = name in self.running
            if name.endswith("eval") or not self.keep_soak_running:
                running = False
                self.running.discard(name)
            return SUPERVISOR.CommandResult(
                0,
                json.dumps(
                    {
                        "Running": running,
                        "ExitCode": 0,
                        "OOMKilled": self.oom and name.endswith("eval"),
                    }
                ),
            )
        if command[:2] == ("docker", "stop"):
            self.running.difference_update(command[4:])
            return SUPERVISOR.CommandResult(0, "stopped\n")
        if command[:2] == ("docker", "logs"):
            return SUPERVISOR.CommandResult(0, "private raw child log\n")
        if command[:2] == ("docker", "rm"):
            self.existing.discard(command[-1])
            self.running.discard(command[-1])
            return SUPERVISOR.CommandResult(0, "removed\n")
        raise AssertionError(command)


def _seed_child_receipts(output: Path) -> None:
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


def test_wrapper_dockerfile_is_separate_pinned_and_minimal() -> None:
    text = (ROOT / "deploy" / "Dockerfile.offline-eval").read_text()
    assert "ARG RAPIDO_BASE_IMAGE" in text
    assert "FROM ${RAPIDO_BASE_IMAGE}" in text
    assert "org.opencontainers.image.revision" in text
    assert "USER 10001:10001" in text
    assert "ENTRYPOINT" not in text
    assert "chmod 0444" in text
    copies = [line for line in text.splitlines() if line.startswith("COPY ")]
    assert len(copies) == 3
    assert any("offline_oracle_pilot.py" in line for line in copies)
    assert any("board_contract_soak.py" in line for line in copies)
    assert any("offline-h24-preregistration-v1.json" in line for line in copies)


def test_fixed_argv_boundaries_and_resources(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    h24 = SUPERVISOR.h24_create_argv(protocol, paths)
    soak = SUPERVISOR.soak_create_argv(protocol, paths)
    descriptor = SUPERVISOR.descriptor_preflight_argv(protocol, paths)

    for argv in (h24, soak, descriptor):
        assert "--init" not in argv
        assert "--read-only" in argv
        assert "--cap-drop=ALL" in argv
        assert "--security-opt=no-new-privileges:true" in argv
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
                    "Config": {
                        "Labels": {
                            "org.opencontainers.image.revision": SOURCE_SHA,
                            "io.incypher.rapido.source-revision": SOURCE_SHA,
                        }
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
    _seed_child_receipts(paths.output)
    runner = DockerFake(paths.output)
    clock = FakeClock()
    receipt = SUPERVISOR.run_evaluation(protocol, paths, runner=runner, clock=clock, finalize=False)

    assert receipt["status"] == "completed"
    starts = [command for command in runner.commands if command[:2] == ("docker", "start")]
    assert starts == [("docker", "start", protocol.h24_name, protocol.soak_name)]
    creates = [command for command in runner.commands if command[:2] == ("docker", "create")]
    barriers = {command[command.index("--start-at-unix-ms") + 1] for command in creates}
    assert len(barriers) == 1
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
    }
    assert clock.monotonic() == 1_000 + 30 + 19_800
    assert not paths.work.exists()
    assert not paths.seed.exists()
    assert paths.auth.exists() and (paths.auth / "auth.json").exists()
    assert paths.output.exists() and (paths.output / SUPERVISOR.SUPERVISOR_RECEIPT).exists()
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in paths.output.iterdir())


def test_deadline_stops_only_running_exact_container_without_filler(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    protocol = replace(protocol, scoring_seconds=2, barrier_delay_seconds=1)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output)
    clock = FakeClock()
    runner = DockerFake(paths.output, keep_soak_running=True, clock=clock)
    SUPERVISOR.run_evaluation(protocol, paths, runner=runner, clock=clock, finalize=False)

    scoring_stops = [
        (command, timestamp)
        for command, timestamp in runner.command_times
        if command[:4] == ("docker", "stop", "--time", "0")
    ]
    assert scoring_stops == [(("docker", "stop", "--time", "0", protocol.soak_name), 1_183.0)]
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


def test_oom_and_child_failures_are_retained_not_dropped(tmp_path: Path) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output)
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
    _seed_child_receipts(paths.output)
    receipt = SUPERVISOR.run_evaluation(
        protocol,
        paths,
        runner=DockerFake(paths.output),
        clock=FakeClock(),
        finalize=False,
    )
    encoded = json.dumps(receipt, sort_keys=True)
    assert str(tmp_path) not in encoded
    assert "private raw child log" not in encoded
    assert "candidate-value" not in encoded
    assert "CTFD_API_TOKEN" not in encoded
    assert "container_id" not in encoded
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
    }


def test_descriptor_preflight_emits_only_frozen_closed_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    paths = _paths(tmp_path, preregistration, registration)

    class DescriptorFake(DockerFake):
        def __call__(self, argv: Any, *, timeout: float | None = None) -> Any:
            command = tuple(argv)
            if command[:4] == ("docker", "start", "--attach", f"{protocol.h24_name}-descriptor"):
                self.commands.append(command)
                raw = {
                    "schema": SUPERVISOR.DESCRIPTOR_SCHEMA,
                    "preregistration_sha256": "public-binding",
                    "source": {},
                    "image": {},
                    "descriptors": protocol.preregistration["descriptor_preflight"],
                    "matched": True,
                }
                path = paths.output / SUPERVISOR.DESCRIPTOR_RECEIPT
                path.write_text(json.dumps(raw))
                path.chmod(0o600)
                return SUPERVISOR.CommandResult(0, "")
            return super().__call__(command, timeout=timeout)

    result = SUPERVISOR.run_descriptor_preflight(
        protocol, paths, runner=DescriptorFake(paths.output)
    )
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
    _seed_child_receipts(paths.output)
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
    assert observed == [0, 5_000, 10_000]
    assert private_inputs_present == [(True, True), (False, False), (False, False)]
    assert receipt["status"] == "completed"


def test_assembly_failure_preserves_private_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    protocol = replace(protocol, scoring_seconds=2, barrier_delay_seconds=1)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output)

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
    _seed_child_receipts(paths.output)
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

    assert observed == [180_000, 184_000, 188_000, 192_000]
    assert receipt["status"] == "failed"
    assert receipt["failure_class"] == "cleanup_timeout"


def test_worker_drain_leaves_tail_inside_outer_cleanup_grace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    protocol, preregistration, registration = _protocol_files(tmp_path)
    protocol = replace(protocol, scoring_seconds=2, barrier_delay_seconds=1)
    paths = _paths(tmp_path, preregistration, registration)
    _seed_child_receipts(paths.output)
    clock = FakeClock()
    observed: list[int] = []

    def finalize(*args: object, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        del args
        observed.append(int(kwargs["cleanup_elapsed_milliseconds"]))
        clock.sleep((3, 3, 4)[len(observed) - 1])
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

    assert observed == [180_000, 183_000, 186_000]
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
