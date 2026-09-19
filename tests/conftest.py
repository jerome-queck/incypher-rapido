from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

import rapido.board_contract as BOARD_CONTRACT


@pytest.fixture
def checkout_offline_pilot(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    module_name = "_rapido_board_contract_offline_pilot"
    monkeypatch.setattr(
        BOARD_CONTRACT,
        "_PACKAGED_OFFLINE_PILOT_DIRECTORY",
        Path(__file__).resolve().parents[1] / "scripts",
    )
    sys.modules.pop(module_name, None)
    yield
    sys.modules.pop(module_name, None)
