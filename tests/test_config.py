from pathlib import Path

import pytest

from rapido.config import ConfigError, RuntimeConfig


def test_defaults_are_a_real_two_lane_practice_profile() -> None:
    config = RuntimeConfig.from_env({})
    assert config.board_url == "https://hackathon.in-cypher.com"
    assert config.model == "gpt-5.6-luna"
    assert config.reasoning_effort == "xhigh"
    assert config.concurrency == 2
    assert config.attempts_per_challenge == 2
    assert config.run_seconds == 19_800


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
        ("RAPIDO_STATE_PATH", "state.sqlite3"),
    ],
)
def test_rejects_unsupported_or_unsafe_configuration(name: str, value: str) -> None:
    with pytest.raises(ConfigError):
        RuntimeConfig.from_env({name: value})


def test_requires_board_token_only_for_board_work() -> None:
    RuntimeConfig.from_env({})
    with pytest.raises(ConfigError, match="CTFD_API_TOKEN"):
        RuntimeConfig.from_env({}, require_board_auth=True)


def test_accepts_explicit_paths() -> None:
    config = RuntimeConfig.from_env(
        {"RAPIDO_STATE_PATH": "/tmp/rapido/test.db", "RAPIDO_WORK_ROOT": "/tmp/rapido/work"}
    )
    assert config.state_path == Path("/tmp/rapido/test.db")
