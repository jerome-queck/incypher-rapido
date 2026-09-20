from types import SimpleNamespace

import pytest

from rapido import cli
from rapido.board import BoardError, Challenge
from rapido.cli import _codex_child_env, _qualified_challenge_ids, build_parser
from rapido.config import RuntimeConfig
from rapido.orchestrator import RunReport


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
    monitor = build_parser().parse_args(["monitor", "--follow", "--interval", "10"])
    assert monitor.command == "monitor"
    assert monitor.follow is True
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


def test_preflight_never_mutates_board_state_or_starts_codex(monkeypatch, capsys) -> None:
    config = RuntimeConfig.from_env({"CTFD_API_TOKEN": "synthetic-preflight-token"})
    reads = []

    class ReadOnlyBoard:
        def anonymous_identity_is_rejected(self):
            reads.append("anonymous")
            return True

        def identity(self):
            reads.append("identity")
            return {"id": 1, "team_id": 1}

        def list_challenges(self):
            reads.append("list")
            return [{"id": 1}]

        def challenge(self, challenge_id):
            reads.append("detail")
            assert challenge_id == 1
            return Challenge(
                1, "Synthetic preflight", "misc", "standard", "", 0, (), False, None, 0, None, None
            )

        def __getattr__(self, name):
            raise AssertionError(f"unexpected Board operation: {name}")

    def forbidden(*args, **kwargs):
        raise AssertionError("preflight must not start native inference or a state writer")

    monkeypatch.setattr(cli.RuntimeConfig, "from_env", classmethod(lambda cls, **kwargs: config))
    monkeypatch.setattr(cli, "BoardClient", lambda *args, **kwargs: ReadOnlyBoard())
    monkeypatch.setattr(cli, "CodexAppClient", forbidden)
    monkeypatch.setattr(cli, "StateStore", forbidden)
    assert cli._preflight() == 0
    assert set(reads) == {"anonymous", "identity", "list", "detail"}
    output = capsys.readouterr().out
    assert '"writes": 0' in output
    assert "synthetic-preflight-token" not in output


def test_run_command_uses_durable_job_control(monkeypatch, capsys) -> None:
    config = RuntimeConfig.from_env({"CTFD_API_TOKEN": "token"})
    board = object()
    runtime = object()
    observed = {}

    async def drive(selected, *, board, runtime):
        observed.update(config=selected, selected_board=board, selected_runtime=runtime)
        return RunReport("run", "completed", 15, 0, 0, 15, 0, 0, 0)

    monkeypatch.setattr(
        cli.RuntimeConfig,
        "from_env",
        classmethod(lambda cls, **kwargs: config),
    )
    monkeypatch.setattr(cli, "validate_codex_home", lambda path: path)
    monkeypatch.setattr(cli, "BoardClient", lambda *args, **kwargs: board)
    monkeypatch.setattr(cli, "CodexAppClient", lambda *args, **kwargs: runtime)
    monkeypatch.setattr(cli.DurableJobControl, "drive", staticmethod(drive))

    assert cli._run() == 0
    assert observed == {
        "config": config,
        "selected_board": board,
        "selected_runtime": runtime,
    }
    assert '"status": "completed"' in capsys.readouterr().out


def test_monitor_is_read_only_and_never_constructs_board_or_runtime(
    monkeypatch, capsys, tmp_path
) -> None:
    state_path = tmp_path / "state.sqlite3"
    monkeypatch.setenv("RAPIDO_STATE_PATH", str(state_path))
    monkeypatch.setenv("CTFD_API_TOKEN", "monitor-must-not-read-this")
    monkeypatch.setenv("TEAM_KEY", "monitor-must-not-read-this-either")
    view = SimpleNamespace(status="completed")
    monkeypatch.setattr(
        cli.RuntimeConfig,
        "from_env",
        classmethod(lambda cls, **kwargs: pytest.fail("full config or credentials read")),
    )
    observed = {}
    monkeypatch.setattr(
        cli.DurableJobControl,
        "monitor_snapshot",
        staticmethod(
            lambda path, run_id=None: observed.setdefault("snapshot", (path, run_id)) and view
        ),
    )
    monkeypatch.setattr(
        cli, "monitor_payload", lambda selected, previous=None: ({"status": selected.status}, None)
    )
    monkeypatch.setattr(cli, "render_text", lambda payload: f"status={payload['status']}")
    monkeypatch.setattr(cli, "BoardClient", lambda *args, **kwargs: pytest.fail("Board opened"))
    monkeypatch.setattr(
        cli, "CodexAppClient", lambda *args, **kwargs: pytest.fail("runtime opened")
    )

    assert (
        cli._monitor(
            run_id=None,
            output_format="text",
            follow=False,
            interval=10,
            record_jsonl=False,
        )
        == 0
    )
    assert capsys.readouterr().out == "status=completed\n"
    assert observed == {"snapshot": (state_path, None)}


def test_monitor_record_never_aliases_state_database(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("RAPIDO_STATE_PATH", str(tmp_path / "rapido-monitor.jsonl"))
    with pytest.raises(ValueError, match="must differ"):
        cli._monitor(
            run_id=None,
            output_format="json",
            follow=False,
            interval=10,
            record_jsonl=True,
        )
