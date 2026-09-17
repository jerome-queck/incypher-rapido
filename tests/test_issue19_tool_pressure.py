from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "issue19_tool_pressure.py"


@pytest.mark.parametrize(
    ("source_commit", "image_digest", "message"),
    (
        (None, None, "RAPIDO_SOURCE_COMMIT"),
        ("HEAD", "sha256:" + "0" * 64, "RAPIDO_SOURCE_COMMIT"),
        ("0" * 40, "latest", "RAPIDO_IMAGE_DIGEST"),
    ),
)
def test_pressure_protocol_rejects_unbound_provenance(
    tmp_path: Path, source_commit: str | None, image_digest: str | None, message: str
) -> None:
    environment = os.environ.copy()
    environment.pop("RAPIDO_SOURCE_COMMIT", None)
    environment.pop("RAPIDO_IMAGE_DIGEST", None)
    if source_commit is not None:
        environment["RAPIDO_SOURCE_COMMIT"] = source_commit
    if image_digest is not None:
        environment["RAPIDO_IMAGE_DIGEST"] = image_digest
    receipt = tmp_path / "receipt.json"
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "--json", str(receipt)],
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 2
    assert message in json.loads(receipt.read_text(encoding="utf-8"))["precondition_error"]
