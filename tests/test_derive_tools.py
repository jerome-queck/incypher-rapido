from __future__ import annotations

import base64
import hashlib

import pytest

from rapido import derive_tools
from rapido.derive_tools import MAX_DERIVE_INPUT_BYTES, derive_artifact, derive_tool_spec
from rapido.tools import ToolError, Workspace


@pytest.mark.parametrize(
    ("encoding", "encoded"),
    [
        ("base64", base64.b64encode(b"calibration=17")),
        ("hex", b"63616c6962726174696f6e3d3137"),
        ("url", b"calibration%3D17"),
    ],
)
def test_derive_artifact_materializes_exact_source_range(tmp_path, encoding, encoded) -> None:
    source = b"header:" + encoded + b":tail"
    (tmp_path / "source.txt").write_bytes(source)
    result = derive_artifact(
        Workspace(tmp_path),
        {"path": "source.txt", "encoding": encoding, "offset": 7, "length": len(encoded)},
    )
    expected = b"calibration=17"
    assert (tmp_path / result["path"]).read_bytes() == expected
    assert result["sha256"] == hashlib.sha256(expected).hexdigest()
    assert result["source_range_sha256"] == hashlib.sha256(encoded).hexdigest()
    assert result["text_preview"] == "calibration=17"


def test_derive_artifact_is_content_addressed_and_does_not_duplicate(tmp_path) -> None:
    encoded = base64.b64encode(b"same output")
    (tmp_path / "source.txt").write_bytes(encoded)
    workspace = Workspace(tmp_path)
    first = derive_artifact(workspace, {"path": "source.txt", "encoding": "base64"})
    second = derive_artifact(workspace, {"path": "source.txt", "encoding": "base64"})
    assert first == second
    assert [path.name for path in (tmp_path / "derived").iterdir()] == [
        hashlib.sha256(b"same output").hexdigest() + ".bin"
    ]


def test_derive_artifact_reports_implicit_range_truncation(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(derive_tools, "MAX_DERIVE_INPUT_BYTES", 4)
    (tmp_path / "source.txt").write_bytes(b"YQ==ignored")
    result = derive_artifact(Workspace(tmp_path), {"path": "source.txt", "encoding": "base64"})
    assert result["source_bytes"] == 11
    assert result["source_length"] == 4
    assert result["source_truncated"] is True


def test_existing_derived_artifact_does_not_reserve_quota_twice(tmp_path) -> None:
    encoded = base64.b64encode(b"a")
    (tmp_path / "source.txt").write_bytes(encoded)
    first = derive_artifact(Workspace(tmp_path), {"path": "source.txt", "encoding": "base64"})
    _, used = Workspace(tmp_path).snapshot()
    second = derive_artifact(
        Workspace(tmp_path, max_workspace_bytes=used),
        {"path": "source.txt", "encoding": "base64"},
    )
    assert second == first


@pytest.mark.parametrize(
    "arguments",
    [
        {"path": "source.txt", "encoding": "rot13"},
        {"path": "source.txt", "encoding": "base64", "offset": -1},
        {"path": "source.txt", "encoding": "base64", "length": MAX_DERIVE_INPUT_BYTES + 1},
        {"path": "source.txt", "encoding": "url", "extra": True},
    ],
)
def test_derive_artifact_rejects_invalid_or_unbounded_requests(tmp_path, arguments) -> None:
    (tmp_path / "source.txt").write_text("%%%%")
    with pytest.raises(ToolError) as error:
        derive_artifact(Workspace(tmp_path), arguments)
    assert error.value.details["schema_version"] == 1
    assert error.value.details["contract_version"] == 1
    assert error.value.details["failure_stage"]
    assert error.value.details["constraint"]
    assert not (tmp_path / "derived").exists()


def test_derive_artifact_refuses_links_and_workspace_overflow(tmp_path) -> None:
    outside = tmp_path.parent / "outside-derived-input"
    outside.write_text("YQ==")
    (tmp_path / "linked").symlink_to(outside)
    with pytest.raises(ToolError, match="multiply linked|symlink"):
        derive_artifact(Workspace(tmp_path), {"path": "linked", "encoding": "base64"})
    (tmp_path / "linked").unlink()

    (tmp_path / "source.txt").write_text("YQ==")
    workspace = Workspace(tmp_path, max_workspace_bytes=4)
    with pytest.raises(ToolError) as caught:
        derive_artifact(workspace, {"path": "source.txt", "encoding": "base64"})
    assert caught.value.code == "workspace_quota"
    assert not (tmp_path / "derived").exists()


def test_derive_tool_spec_is_closed_and_path_only() -> None:
    schema = derive_tool_spec()["inputSchema"]
    assert schema["required"] == ["path", "encoding"]
    assert schema["additionalProperties"] is False
    assert "data" not in schema["properties"]
