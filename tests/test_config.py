from pathlib import Path

import pytest

from rapido.config import ConfigError, RuntimeConfig, validate_codex_home


def test_defaults_are_a_real_two_lane_practice_profile() -> None:
    config = RuntimeConfig.from_env({})
    assert config.board_url == "https://hackathon.in-cypher.com"
    assert config.model == "gpt-5.6-luna"
    assert config.reasoning_effort == "xhigh"
    assert config.concurrency == 2
    assert config.attempts_per_challenge == 2
    assert config.run_seconds == 19_800
    assert config.max_artifact_bytes == 64 * 1024 * 1024
    assert config.max_challenge_bytes == 128 * 1024 * 1024
    assert config.max_workspace_bytes == 512 * 1024 * 1024
    assert config.max_lane_workspace_bytes == 192 * 1024 * 1024


def test_secrets_are_never_in_public_record() -> None:
    config = RuntimeConfig.from_env({"CTFD_API_TOKEN": "token-value", "TEAM_KEY": "team-value"})
    encoded = repr(config.public_record())
    assert "token-value" not in encoded
    assert "team-value" not in encoded
    assert config.public_record()["board_token_present"] is True


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("CTFD_URL", "http://hackathon.in-cypher.com"),
        ("CTFD_URL", "https://user:pass@hackathon.in-cypher.com"),
        ("CTFD_URL", "https://hackathon.in-cypher.com/path"),
        ("CTFD_URL", "https://attacker.example"),
        ("CTFD_URL", "https://hackathon.in-cypher.com:99999"),
        ("RAPIDO_CONCURRENCY", "1"),
        ("RAPIDO_REASONING_EFFORT", "extreme"),
        ("RAPIDO_SUBMIT_CANDIDATES", "yes"),
        ("RAPIDO_STATE_PATH", "state.sqlite3"),
        ("RAPIDO_MAX_CHALLENGE_BYTES", "1024"),
        ("RAPIDO_MAX_WORKSPACE_BYTES", "1024"),
    ],
)
def test_rejects_unsupported_or_unsafe_configuration(name: str, value: str) -> None:
    with pytest.raises(ConfigError):
        RuntimeConfig.from_env({name: value})


def test_workspace_budget_must_cover_all_lane_copies() -> None:
    with pytest.raises(ConfigError, match="source plus every lane"):
        RuntimeConfig.from_env({"RAPIDO_ATTEMPTS_PER_CHALLENGE": "4"})


def test_requires_board_token_only_for_board_work() -> None:
    RuntimeConfig.from_env({})
    with pytest.raises(ConfigError, match="CTFD_API_TOKEN"):
        RuntimeConfig.from_env({}, require_board_auth=True)


def test_accepts_explicit_paths() -> None:
    config = RuntimeConfig.from_env(
        {
            "RAPIDO_STATE_PATH": "/tmp/rapido/test.db",
            "RAPIDO_WORK_ROOT": "/tmp/rapido/work",
            "RAPIDO_CODEX_HOME": "/tmp/rapido/codex",
            "RAPIDO_SUBMIT_CANDIDATES": "true",
        }
    )
    assert config.state_path == Path("/tmp/rapido/test.db")
    assert config.codex_home == Path("/tmp/rapido/codex")
    assert config.submit_candidates is True


def test_native_auth_home_must_be_private_regular_and_writable(tmp_path: Path) -> None:
    home = tmp_path / "codex"
    home.mkdir(mode=0o700)
    auth = home / "auth.json"
    auth.write_text("{}")
    auth.chmod(0o600)
    assert validate_codex_home(home) == auth
    auth.chmod(0o644)
    with pytest.raises(ConfigError, match="0600"):
        validate_codex_home(home)
    auth.chmod(0o400)
    with pytest.raises(ConfigError, match="readable and writable"):
        validate_codex_home(home)


def test_native_auth_home_rejects_capability_config(tmp_path: Path) -> None:
    home = tmp_path / "codex"
    home.mkdir(mode=0o700)
    auth = home / "auth.json"
    auth.write_text("{}")
    auth.chmod(0o600)
    (home / "config.toml").write_text("[mcp_servers.untrusted]\n")
    with pytest.raises(ConfigError, match="capability config"):
        validate_codex_home(home)
