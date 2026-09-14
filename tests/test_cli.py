import pytest

from rapido.board import BoardError
from rapido.cli import _codex_child_env, _qualified_challenge_ids, build_parser
from rapido.config import RuntimeConfig


def test_run_command_exists_and_codex_child_env_excludes_board_credentials() -> None:
    config = RuntimeConfig.from_env(
        {
            "CTFD_API_TOKEN": "board-token",
            "TEAM_KEY": "team-key",
            "RAPIDO_CODEX_HOME": "/auth/private",
        }
    )
    assert build_parser().parse_args(["run"]).command == "run"
    pending = build_parser().parse_args(["pending"])
    assert pending.command == "pending"
    reconcile = build_parser().parse_args(
        [
            "reconcile",
            "--challenge-id",
            "7",
            "--candidate-sha256",
            "a" * 64,
            "--outcome",
            "not-delivered",
        ]
    )
    assert reconcile.command == "reconcile"
    child = _codex_child_env(config)
    assert child["CODEX_HOME"] == "/auth/private"
    assert "board-token" not in repr(child)
    assert "team-key" not in repr(child)
    assert set(child) == {"CODEX_HOME", "HOME", "PATH", "TERM", "NO_COLOR"}


def test_preflight_rejects_duplicate_challenge_ids() -> None:
    with pytest.raises(BoardError, match="incoherent"):
        _qualified_challenge_ids([{"id": 7}, {"id": 7}], [{"id": 7}, {"id": 7}])
