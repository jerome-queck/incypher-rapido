"""Explicit offline capability profile, separate from production authority parsing."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from .config import ConfigError, RuntimeConfig

OFFLINE_PROFILE_SCHEMA = "rapido-offline-profile-v1"
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_TASK_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_PRODUCTION_AUTHORITY_ENV = frozenset({"CTFD_URL", "CTFD_API_TOKEN", "TEAM_KEY"})
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")


def _identifier(value: str, label: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ConfigError(f"{label} is not a closed identifier")
    return value


def _task_identifier(value: str) -> str:
    if type(value) is not str or _TASK_IDENTIFIER.fullmatch(value) is None:
        raise ConfigError("offline task id is not a closed identifier")
    return value


def assert_offline_environment(env: Mapping[str, str] | None = None) -> None:
    """Fail closed if production Board authority enters an offline process."""
    values = os.environ if env is None else env
    present = sorted(name for name in _PRODUCTION_AUTHORITY_ENV if name in values)
    if present:
        raise ConfigError("production Board authority variables are forbidden offline")


def offline_child_env(
    config: RuntimeConfig, env: Mapping[str, str] | None = None
) -> dict[str, str]:
    """Return the same credential-free native-client allowlist used in production."""
    assert_offline_environment(env)
    return {
        "CODEX_HOME": str(config.codex_home),
        "HOME": str(config.codex_home),
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "TERM": "dumb",
        "NO_COLOR": "1",
    }


@dataclass(frozen=True)
class OfflineTaskRegistration:
    """Candidate-free task identity frozen before an offline run."""

    board_id: int
    task_id: str
    generator_version: str
    checker_version: str
    service_version: str = "none"

    def public_record(self) -> dict[str, object]:
        return {
            "board_id": self.board_id,
            "task_id": self.task_id,
            "generator_version": self.generator_version,
            "checker_version": self.checker_version,
            "service_version": self.service_version,
        }


@dataclass(frozen=True)
class OfflineRuntimeConfig(RuntimeConfig):
    """Runtime knobs for direct-injection evaluation; never built from Board env."""

    offline_profile_id: str
    catalogue_version: str
    board_implementation_version: str
    runner_image: str
    task_registrations: tuple[OfflineTaskRegistration, ...]

    @classmethod
    def build(
        cls,
        *,
        offline_profile_id: str,
        catalogue_version: str,
        board_implementation_version: str,
        state_path: Path,
        work_root: Path,
        codex_home: Path,
        runner_image: str,
        task_registrations: Sequence[OfflineTaskRegistration],
        model: str = "gpt-daybreak-blue-latest",
        reasoning_effort: str = "xhigh",
        specialist_model: str = "gpt-5.6-luna",
        specialist_reasoning_efforts: tuple[str, ...] = ("max", "xhigh", "max"),
        lead_lanes: int = 2,
        peer_profile: str = "mixed_v1",
        active_challenges: int = 5,
        episodes_per_challenge: int = 3,
        attempts_per_challenge: int = 4,
        attempt_seconds: int = 800,
        run_seconds: int = 3_600,
        max_artifact_bytes: int = 64 * 1024 * 1024,
        max_challenge_bytes: int = 128 * 1024 * 1024,
        max_workspace_bytes: int = 500 * 1024 * 1024 * 1024,
        codex_binary: str = "codex",
        memory_arm: str = "typed_challenge_v1",
    ) -> OfflineRuntimeConfig:
        """Build directly from a frozen registration, bypassing production env parsing."""
        profile_id = _identifier(offline_profile_id, "offline profile id")
        catalogue = _identifier(catalogue_version, "catalogue version")
        implementation = _identifier(board_implementation_version, "Board implementation version")
        if type(runner_image) is not str or _IMAGE_DIGEST.fullmatch(runner_image) is None:
            raise ConfigError("offline runner image must be an exact digest")
        paths = (state_path, work_root, codex_home)
        if any(not isinstance(path, Path) or not path.is_absolute() for path in paths):
            raise ConfigError("offline runtime paths must be absolute Path values")
        tasks = tuple(task_registrations)
        if not tasks or any(type(task) is not OfflineTaskRegistration for task in tasks):
            raise ConfigError("offline task registrations are invalid")
        ids = tuple(task.board_id for task in tasks)
        if (
            any(type(value) is not int or value <= 0 for value in ids)
            or len(ids) != len(set(ids))
            or len({task.task_id for task in tasks}) != len(tasks)
        ):
            raise ConfigError("offline task registrations must have unique positive identities")
        for task in tasks:
            _task_identifier(task.task_id)
            _identifier(task.generator_version, "offline generator version")
            _identifier(task.checker_version, "offline checker version")
            _identifier(task.service_version, "offline service version")
        if len({task.service_version for task in tasks if task.service_version != "none"}) > 1:
            raise ConfigError("offline dynamic tasks require one registered service source")
        if not 1 <= active_challenges <= min(8, len(ids)):
            raise ConfigError("offline active challenge count is invalid")
        if not 1 <= episodes_per_challenge <= 4:
            raise ConfigError("offline episode count is invalid")
        if not 2 <= attempts_per_challenge <= 8:
            raise ConfigError("offline lane count is invalid")
        if not 1 <= lead_lanes <= attempts_per_challenge:
            raise ConfigError("offline lead lane count is invalid")
        if peer_profile not in {"mixed_v1", "uniform_v1"}:
            raise ConfigError("offline peer profile is invalid")
        if not specialist_reasoning_efforts or len(specialist_reasoning_efforts) > 8:
            raise ConfigError("offline specialist efforts are invalid")
        if attempt_seconds < 600 or run_seconds < 60:
            raise ConfigError("offline time budget is below the supported floor")
        if max_artifact_bytes < 1024 or max_challenge_bytes < max_artifact_bytes:
            raise ConfigError("offline artifact budget is invalid")
        minimum_workspace = active_challenges * max_challenge_bytes * (attempts_per_challenge + 1)
        if max_workspace_bytes < minimum_workspace:
            raise ConfigError("offline workspace budget cannot cover admitted lane copies")
        efforts = {reasoning_effort, *specialist_reasoning_efforts}
        if not efforts or not efforts <= {"low", "medium", "high", "xhigh", "max", "ultra"}:
            raise ConfigError("offline reasoning effort is invalid")
        descriptors = (model, specialist_model, codex_binary)
        if any(
            type(value) is not str
            or not value
            or len(value) > 256
            or any(ord(character) < 32 for character in value)
            for value in descriptors
        ):
            raise ConfigError("offline model and binary descriptors must be explicit")
        if memory_arm not in {"lane_local_v1", "typed_challenge_v1"}:
            raise ConfigError("offline memory arm is invalid")

        return cls(
            board_url="",
            board_token="",
            team_key="",
            board_timeout_seconds=1,
            model=model,
            reasoning_effort=reasoning_effort,
            specialist_model=specialist_model,
            specialist_reasoning_efforts=specialist_reasoning_efforts,
            lead_lanes=lead_lanes,
            peer_profile=peer_profile,
            concurrency=active_challenges * attempts_per_challenge,
            active_challenges=active_challenges,
            episodes_per_challenge=episodes_per_challenge,
            dynamic_concurrency=1,
            attempts_per_challenge=attempts_per_challenge,
            attempt_seconds=attempt_seconds,
            instance_ready_seconds=6,
            instance_cleanup_seconds=3,
            run_seconds=run_seconds,
            max_artifact_bytes=max_artifact_bytes,
            max_challenge_bytes=max_challenge_bytes,
            max_workspace_bytes=max_workspace_bytes,
            state_path=state_path,
            work_root=work_root,
            codex_home=codex_home,
            codex_binary=codex_binary,
            profile=profile_id,
            memory_arm=memory_arm,
            challenge_ids=ids,
            focus_challenge_ids=(),
            submit_candidates=True,
            manage_dynamic_instances=True,
            watch_board=False,
            board_watch_seconds=15,
            board_full_refresh_seconds=60,
            offline_profile_id=profile_id,
            catalogue_version=catalogue,
            board_implementation_version=implementation,
            runner_image=runner_image,
            task_registrations=tasks,
        )

    def offline_board_registration(self) -> dict[str, object]:
        """Exact public facts that the instantiated Board must match before model work."""
        dynamic_versions = {
            task.service_version
            for task in self.task_registrations
            if task.service_version != "none"
        }
        if len(dynamic_versions) > 1:
            raise ConfigError("offline dynamic tasks require one registered service source")
        service_runtime: dict[str, object] | None = None
        if dynamic_versions:
            service_runtime = {
                "backend": "docker-service-v1",
                "runner_image": self.runner_image,
                "source_version": next(iter(dynamic_versions)),
                "profile_id": "small-v1",
                "cpu_cores": 1.0,
                "memory_bytes": 256 * 1024 * 1024,
                "pids_limit": 64,
                "writable_tmpfs_bytes": 64 * 1024 * 1024,
                "internal_port": 8080,
                "hard_lifetime_seconds": 900,
                "internal_network": True,
                "arbitrary_egress": False,
                "published_loopback_only": True,
            }
        return {
            "offline_profile_id": self.offline_profile_id,
            "catalogue_version": self.catalogue_version,
            "implementation_version": self.board_implementation_version,
            "task_registrations": [task.public_record() for task in self.task_registrations],
            "service_runtime": service_runtime,
        }

    def public_record(self) -> dict[str, object]:
        """Sanitized registration record with no authority, credential, or host path."""
        return {
            "schema": OFFLINE_PROFILE_SCHEMA,
            "offline_profile_id": self.offline_profile_id,
            "catalogue_version": self.catalogue_version,
            "board_implementation_version": self.board_implementation_version,
            "runner_image": self.runner_image,
            "task_registrations": [task.public_record() for task in self.task_registrations],
            "service_runtime": self.offline_board_registration()["service_runtime"],
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "specialist_model": self.specialist_model,
            "specialist_reasoning_efforts": list(self.specialist_reasoning_efforts),
            "lead_lanes": self.lead_lanes,
            "peer_profile": self.peer_profile,
            "concurrency": self.concurrency,
            "active_challenges": self.active_challenges,
            "episodes_per_challenge": self.episodes_per_challenge,
            "dynamic_concurrency": self.dynamic_concurrency,
            "attempts_per_challenge": self.attempts_per_challenge,
            "attempt_seconds": self.attempt_seconds,
            "board_timeout_seconds": self.board_timeout_seconds,
            "instance_ready_seconds": self.instance_ready_seconds,
            "instance_cleanup_seconds": self.instance_cleanup_seconds,
            "run_seconds": self.run_seconds,
            "max_artifact_bytes": self.max_artifact_bytes,
            "max_challenge_bytes": self.max_challenge_bytes,
            "max_workspace_bytes": self.max_workspace_bytes,
            "max_challenge_workspace_bytes": self.max_challenge_workspace_bytes,
            "max_lane_workspace_bytes": self.max_lane_workspace_bytes,
            "memory_arm": self.memory_arm,
            "selected_challenge_count": len(self.challenge_ids),
            "submit_candidates": self.submit_candidates,
            "manage_dynamic_instances": self.manage_dynamic_instances,
            "watch_board": self.watch_board,
        }
