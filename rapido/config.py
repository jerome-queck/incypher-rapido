"""Strict runtime configuration with no silent capability fallbacks."""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


class ConfigError(ValueError):
    """A configuration value is missing, unsafe, or unsupported."""


def validate_codex_home(path: Path) -> Path:
    """Validate a private, writable, file-backed native subscription home."""
    try:
        directory = path.lstat()
    except OSError as exc:
        raise ConfigError("RAPIDO_CODEX_HOME is not accessible") from exc
    if (
        stat.S_ISLNK(directory.st_mode)
        or not stat.S_ISDIR(directory.st_mode)
        or directory.st_uid not in {0, os.geteuid()}
    ):
        raise ConfigError("RAPIDO_CODEX_HOME must be a real directory")
    if directory.st_mode & 0o077:
        raise ConfigError("RAPIDO_CODEX_HOME must not grant group or other access")
    if not os.access(path, os.R_OK | os.W_OK | os.X_OK):
        raise ConfigError("RAPIDO_CODEX_HOME must be readable and writable")
    auth_file = path / "auth.json"
    try:
        auth = auth_file.lstat()
    except OSError as exc:
        raise ConfigError("native Codex auth.json is missing") from exc
    if (
        stat.S_ISLNK(auth.st_mode)
        or not stat.S_ISREG(auth.st_mode)
        or auth.st_uid not in {0, os.geteuid()}
    ):
        raise ConfigError("native Codex auth.json must be a regular file")
    if auth.st_mode & 0o077:
        raise ConfigError("native Codex auth.json must have mode 0600 or stricter")
    if stat.S_IMODE(auth.st_mode) & 0o600 != 0o600 or not os.access(auth_file, os.R_OK | os.W_OK):
        raise ConfigError("native Codex auth.json must be owner-readable and writable")
    for name in ("config.toml", "config.json", "mcp.json"):
        if (path / name).exists() or (path / name).is_symlink():
            raise ConfigError("dedicated native Codex home must not contain capability config")
    return auth_file


def _text(env: Mapping[str, str], name: str, default: str) -> str:
    value = env.get(name, default).strip()
    if not value or any(ord(char) < 32 for char in value):
        raise ConfigError(f"{name} must be non-empty printable text")
    return value


def _integer(env: Mapping[str, str], name: str, default: int, *, minimum: int, maximum: int) -> int:
    raw = env.get(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ConfigError(f"{name} must be between {minimum} and {maximum}")
    return value


def _path(env: Mapping[str, str], name: str, default: str) -> Path:
    raw = _text(env, name, default)
    path = Path(raw)
    if not path.is_absolute():
        raise ConfigError(f"{name} must be an absolute path")
    return path


def _boolean(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name, "true" if default else "false").strip().lower()
    if raw == "true":
        return True
    if raw == "false":
        return False
    raise ConfigError(f"{name} must be true or false")


def _challenge_ids(env: Mapping[str, str]) -> tuple[int, ...]:
    raw = env.get("RAPIDO_CHALLENGE_IDS", "").strip()
    if not raw:
        return ()
    parts = raw.split(",")
    if len(parts) > 1000:
        raise ConfigError("RAPIDO_CHALLENGE_IDS exceeds the challenge limit")
    try:
        values = tuple(int(part.strip()) for part in parts)
    except ValueError as exc:
        raise ConfigError("RAPIDO_CHALLENGE_IDS must be comma-separated integers") from exc
    if any(value <= 0 for value in values) or len(values) != len(set(values)):
        raise ConfigError("RAPIDO_CHALLENGE_IDS must contain unique positive integers")
    return values


def _origin(env: Mapping[str, str]) -> str:
    value = _text(env, "CTFD_URL", "https://hackathon.in-cypher.com").rstrip("/")
    parsed = urlsplit(value)
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigError("CTFD_URL contains an invalid port") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "hackathon.in-cypher.com"
        or parsed.username
        or parsed.password
        or port not in (None, 443)
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ConfigError("CTFD_URL must be the credential-free official HTTPS origin")
    return value


@dataclass(frozen=True)
class RuntimeConfig:
    board_url: str
    board_token: str
    team_key: str
    model: str
    reasoning_effort: str
    concurrency: int
    attempts_per_challenge: int
    attempt_seconds: int
    run_seconds: int
    max_artifact_bytes: int
    max_challenge_bytes: int
    max_workspace_bytes: int
    state_path: Path
    work_root: Path
    codex_home: Path
    codex_binary: str
    profile: str
    challenge_ids: tuple[int, ...]
    wrong_submission_ceiling: int
    submit_candidates: bool
    manage_dynamic_instances: bool

    @classmethod
    def from_env(
        cls, env: Mapping[str, str] | None = None, *, require_board_auth: bool = False
    ) -> RuntimeConfig:
        values = os.environ if env is None else env
        token = values.get("CTFD_API_TOKEN", "").strip()
        team_key = values.get("TEAM_KEY", "").strip()
        if require_board_auth and not token:
            raise ConfigError("CTFD_API_TOKEN is required for authenticated Board work")
        for name, value in (("CTFD_API_TOKEN", token), ("TEAM_KEY", team_key)):
            if value and (
                len(value) > 1024 or not value.isascii() or any(c.isspace() for c in value)
            ):
                raise ConfigError(f"{name} must be bounded ASCII without whitespace")

        effort = _text(values, "RAPIDO_REASONING_EFFORT", "xhigh")
        supported_efforts = {"low", "medium", "high", "xhigh", "max", "ultra"}
        if effort not in supported_efforts:
            raise ConfigError(
                "RAPIDO_REASONING_EFFORT must be low, medium, high, xhigh, max, or ultra"
            )

        profile = _text(values, "RAPIDO_PROFILE", "practice")
        if profile not in {"economy", "practice", "competition"}:
            raise ConfigError("RAPIDO_PROFILE must be economy, practice, or competition")

        max_artifact_bytes = _integer(
            values,
            "RAPIDO_MAX_ARTIFACT_BYTES",
            64 * 1024 * 1024,
            minimum=1024,
            maximum=2 * 1024 * 1024 * 1024,
        )
        max_challenge_bytes = _integer(
            values,
            "RAPIDO_MAX_CHALLENGE_BYTES",
            128 * 1024 * 1024,
            minimum=1024,
            maximum=2 * 1024 * 1024 * 1024,
        )
        if max_challenge_bytes < max_artifact_bytes:
            raise ConfigError("RAPIDO_MAX_CHALLENGE_BYTES must cover one maximum artifact")
        attempts_per_challenge = _integer(
            values, "RAPIDO_ATTEMPTS_PER_CHALLENGE", 2, minimum=2, maximum=8
        )
        max_workspace_bytes = _integer(
            values,
            "RAPIDO_MAX_WORKSPACE_BYTES",
            500 * 1024 * 1024 * 1024,
            minimum=3 * 1024,
            maximum=500 * 1024 * 1024 * 1024,
        )
        minimum_workspace_bytes = max_challenge_bytes * (attempts_per_challenge + 1)
        if max_workspace_bytes < minimum_workspace_bytes:
            raise ConfigError(
                "RAPIDO_MAX_WORKSPACE_BYTES must cover source plus every lane artifact copy"
            )

        return cls(
            board_url=_origin(values),
            board_token=token,
            team_key=team_key,
            model=_text(values, "RAPIDO_MODEL", "gpt-6-astra"),
            reasoning_effort=effort,
            concurrency=_integer(values, "RAPIDO_CONCURRENCY", 2, minimum=2, maximum=8),
            attempts_per_challenge=attempts_per_challenge,
            attempt_seconds=_integer(
                values, "RAPIDO_ATTEMPT_SECONDS", 900, minimum=15, maximum=7200
            ),
            run_seconds=_integer(values, "RAPIDO_RUN_SECONDS", 19_800, minimum=60, maximum=172_800),
            max_artifact_bytes=max_artifact_bytes,
            max_challenge_bytes=max_challenge_bytes,
            max_workspace_bytes=max_workspace_bytes,
            state_path=_path(values, "RAPIDO_STATE_PATH", "/state/rapido.sqlite3"),
            work_root=_path(values, "RAPIDO_WORK_ROOT", "/state/work"),
            codex_home=_path(values, "RAPIDO_CODEX_HOME", "/auth/codex"),
            codex_binary=_text(values, "RAPIDO_CODEX_BINARY", "codex"),
            profile=profile,
            challenge_ids=_challenge_ids(values),
            wrong_submission_ceiling=_integer(
                values, "RAPIDO_WRONG_SUBMISSION_CEILING", 2, minimum=0, maximum=10
            ),
            submit_candidates=_boolean(values, "RAPIDO_SUBMIT_CANDIDATES", False),
            manage_dynamic_instances=_boolean(values, "RAPIDO_MANAGE_DYNAMIC_INSTANCES", False),
        )

    def public_record(self) -> dict[str, object]:
        """Effective non-secret settings suitable for logs and run evidence."""
        return {
            "board_url": self.board_url,
            "model": self.model,
            "reasoning_effort": self.reasoning_effort,
            "concurrency": self.concurrency,
            "attempts_per_challenge": self.attempts_per_challenge,
            "attempt_seconds": self.attempt_seconds,
            "run_seconds": self.run_seconds,
            "max_artifact_bytes": self.max_artifact_bytes,
            "max_challenge_bytes": self.max_challenge_bytes,
            "max_workspace_bytes": self.max_workspace_bytes,
            "max_lane_workspace_bytes": self.max_lane_workspace_bytes,
            "state_path": str(self.state_path),
            "work_root": str(self.work_root),
            "codex_home": str(self.codex_home),
            "profile": self.profile,
            "challenge_ids": list(self.challenge_ids),
            "wrong_submission_ceiling": self.wrong_submission_ceiling,
            "submit_candidates": self.submit_candidates,
            "manage_dynamic_instances": self.manage_dynamic_instances,
            "board_token_present": bool(self.board_token),
            "team_key_present": bool(self.team_key),
        }

    @property
    def max_lane_workspace_bytes(self) -> int:
        """Conservative lane cap preserving the aggregate challenge workspace cap."""
        return (self.max_workspace_bytes - self.max_challenge_bytes) // self.attempts_per_challenge
