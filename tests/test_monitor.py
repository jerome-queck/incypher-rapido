from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from rapido import monitor


def test_resource_snapshot_reads_only_bounded_cgroup_counters(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "cpu.stat").write_text("usage_usec 2500000\n")
    (tmp_path / "cpu.max").write_text("1200000 100000\n")
    (tmp_path / "memory.current").write_text("4096\n")
    (tmp_path / "memory.peak").write_text("8192\n")
    (tmp_path / "memory.max").write_text("max\n")
    (tmp_path / "memory.events").write_text("oom 0\n")
    (tmp_path / "pids.current").write_text("20\n")
    (tmp_path / "pids.peak").write_text("30\n")
    (tmp_path / "pids.max").write_text("256\n")
    (tmp_path / "pids.events").write_text("max 0\n")
    monkeypatch.setattr(monitor, "_cgroup_root", lambda: tmp_path)

    value, cursor = monitor.resource_snapshot()

    assert value["available"] is True
    assert value["cpu"]["limit_cores"] == 12
    assert value["memory"] == {
        "current_bytes": 4096,
        "peak_bytes": 8192,
        "limit_bytes": None,
        "events": {"oom": 0},
    }
    assert value["pids"]["limit"] == 256
    assert cursor is not None


def test_private_jsonl_is_append_only_private_and_rejects_symlinks(tmp_path: Path) -> None:
    path = tmp_path / "rapido-monitor.jsonl"
    monitor.append_private_jsonl(path, {"schema": "rapido.monitor.v1", "sample": 1})
    monitor.append_private_jsonl(path, {"schema": "rapido.monitor.v1", "sample": 2})

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [json.loads(line)["sample"] for line in path.read_text().splitlines()] == [1, 2]
    link = tmp_path / "link.jsonl"
    link.symlink_to(path)
    with pytest.raises(OSError):
        monitor.append_private_jsonl(link, {"sample": 3})
    hardlink = tmp_path / "hardlink.jsonl"
    os.link(path, hardlink)
    with pytest.raises(ValueError, match="singly linked"):
        monitor.append_private_jsonl(hardlink, {"sample": 4})
