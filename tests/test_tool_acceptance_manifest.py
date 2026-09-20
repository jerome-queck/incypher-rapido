from __future__ import annotations

import json
import re
from pathlib import Path

from scripts.tooling_acceptance import PINNED_PARSERS

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "deploy/tool-acceptance-manifest-v1.json"
REQUIREMENTS = ROOT / "deploy/tool-requirements.txt"


def test_selected_tool_manifest_matches_hashed_install_contract() -> None:
    document = json.loads(MANIFEST.read_text(encoding="utf-8"))
    assert document["schema_version"] == 1
    assert document["runtime"]["architectures"] == ["linux/amd64", "linux/arm64"]
    tools = document["tools"]
    assert [tool["distribution"] for tool in tools] == [
        "hl7",
        "lief",
        "pydicom",
        "scapy",
        "yara-python",
    ]
    requirements = REQUIREMENTS.read_text(encoding="utf-8")
    assert requirements.count("#sha256=") == 7
    assert len(re.findall(r"#sha256=[0-9a-f]{64}(?:\s|$)", requirements)) == 7
    for tool in tools:
        distribution = tool["distribution"]
        version = tool["version"]
        assert PINNED_PARSERS[distribution][1] == version
        normalized = distribution.replace("-", "[_-]")
        assert re.search(rf"^{normalized}.*-{re.escape(version)}-", requirements, re.MULTILINE)
        assert tool["license"]
        assert tool["capability"]
        assert tool["invocation"]
        assert tool["fixture"]
        assert tool["failure"]
        assert tool["rollback"]


def test_dockerfile_uses_hash_enforcement_for_selected_tools() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY deploy/tool-requirements.txt /src/tool-requirements.txt" in dockerfile
    assert "--no-deps --require-hashes --requirement /src/tool-requirements.txt" in dockerfile
