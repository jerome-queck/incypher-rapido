"""Command-line entrypoint."""

from __future__ import annotations

import argparse
import json
import sys

from .board import BoardClient, BoardError
from .config import ConfigError, RuntimeConfig


def _preflight() -> int:
    config = RuntimeConfig.from_env(require_board_auth=True)
    board = BoardClient(
        config.board_url,
        config.board_token,
        artifact_limit=config.max_artifact_bytes,
    )
    identity = board.identity()
    rows = board.list_challenges()
    ids = []
    categories: dict[str, int] = {}
    types: dict[str, int] = {}
    for row in rows:
        challenge_id = row.get("id")
        if type(challenge_id) is not int or challenge_id <= 0:
            raise BoardError("challenge list contains an invalid id")
        detail = board.challenge(challenge_id)
        ids.append(detail.id)
        categories[detail.category] = categories.get(detail.category, 0) + 1
        types[detail.type] = types.get(detail.type, 0) + 1
    report = {
        "status": "ok",
        "authenticated": True,
        "identity_id": identity["id"],
        "team_id_present": type(identity.get("team_id")) is int,
        "challenge_count": len(ids),
        "challenge_ids": sorted(ids),
        "categories": dict(sorted(categories.items())),
        "types": dict(sorted(types.items())),
        "writes": 0,
        "effective_config": config.public_record(),
    }
    print(json.dumps(report, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rapido")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("preflight", help="authenticated read-only Board contract check")
    subcommands.add_parser("config", help="print effective non-secret configuration")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "preflight":
            return _preflight()
        if arguments.command == "config":
            print(json.dumps(RuntimeConfig.from_env().public_record(), sort_keys=True))
            return 0
    except (BoardError, ConfigError) as exc:
        print(json.dumps({"status": "error", "error": str(exc)}), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
