"""Sanitized, low-overhead live-run monitoring."""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .control import MonitorView


def _integer_file(path: Path) -> int | None:
    try:
        raw = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError):
        return None
    if raw == "max":
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _keyed_file(path: Path) -> dict[str, int]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return {}
    values: dict[str, int] = {}
    for line in lines:
        fields = line.split()
        if len(fields) != 2:
            continue
        try:
            values[fields[0]] = int(fields[1])
        except ValueError:
            continue
    return values


def _cgroup_root() -> Path | None:
    try:
        lines = Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return None
    unified = next((line.removeprefix("0::") for line in lines if line.startswith("0::")), None)
    if unified is None:
        return None
    relative = unified.lstrip("/")
    return Path("/sys/fs/cgroup") / relative


def resource_snapshot(
    previous: tuple[float, int] | None = None,
) -> tuple[dict[str, Any], tuple[float, int] | None]:
    """Read this container's cgroup-v2 counters; never inspect host processes."""
    root = _cgroup_root()
    if root is None:
        return {"available": False, "scope": "self_cgroup"}, None
    cpu = _keyed_file(root / "cpu.stat")
    usage_usec = cpu.get("usage_usec")
    if usage_usec is None:
        return {"available": False, "scope": "self_cgroup"}, None
    sampled = time.monotonic()
    used_cores: float | None = None
    if previous is not None and sampled > previous[0] and usage_usec >= previous[1]:
        used_cores = round((usage_usec - previous[1]) / 1_000_000 / (sampled - previous[0]), 3)
    cpu_max: float | None = None
    try:
        quota, period = (root / "cpu.max").read_text(encoding="ascii").split()
        if quota != "max" and int(period) > 0:
            cpu_max = round(int(quota) / int(period), 3)
    except (OSError, UnicodeError, ValueError):
        pass
    result: dict[str, Any] = {
        "available": True,
        "scope": "self_cgroup",
        "cpu": {
            "used_cores": used_cores,
            "limit_cores": cpu_max,
            "usage_seconds": round(usage_usec / 1_000_000, 3),
        },
        "memory": {
            "current_bytes": _integer_file(root / "memory.current"),
            "peak_bytes": _integer_file(root / "memory.peak"),
            "limit_bytes": _integer_file(root / "memory.max"),
            "events": _keyed_file(root / "memory.events"),
        },
        "pids": {
            "current": _integer_file(root / "pids.current"),
            "peak": _integer_file(root / "pids.peak"),
            "limit": _integer_file(root / "pids.max"),
            "events": _keyed_file(root / "pids.events"),
        },
    }
    return result, (sampled, usage_usec)


def monitor_payload(
    view: MonitorView, previous: tuple[float, int] | None = None
) -> tuple[dict[str, Any], tuple[float, int] | None]:
    resources, cursor = resource_snapshot(previous)
    payload = asdict(view)
    payload["resources"] = resources
    return payload, cursor


def render_text(payload: dict[str, Any]) -> str:
    resources = payload["resources"]
    cpu = resources.get("cpu", {}).get("used_cores") if resources["available"] else None
    memory = resources.get("memory", {}).get("current_bytes") if resources["available"] else None
    pids = resources.get("pids", {}).get("current") if resources["available"] else None
    memory_gib = None if memory is None else round(memory / 1024**3, 2)
    return (
        f"run={payload['run_id']} status={payload['status']} "
        f"remaining={payload['remaining_seconds']}s watching={payload['watching']} "
        f"active={payload['active_challenge_ids']} queued={payload['queued_challenge_ids']} "
        f"instance_wait={payload['instance_waiting_challenge_ids']} "
        f"terminal={len(payload['terminal_challenge_ids'])}/{payload['catalogue_count']} "
        f"reserved_lanes={payload['reserved_lane_count']} "
        f"completed_waiting={payload['completed_waiting_lane_count']} "
        f"tools={payload['tool_call_count']} continuations={payload['continuation_count']} "
        f"submissions={dict(payload['submission_outcomes'])} "
        f"cpu={cpu}cores memory={memory_gib}GiB pids={pids}"
    )


def append_private_jsonl(path: Path, payload: dict[str, Any]) -> None:
    """Append one private canonical sample without following a symlink."""
    flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("monitor record must be a singly linked regular file")
        os.fchmod(descriptor, 0o600)
        encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
        offset = 0
        while offset < len(encoded):
            offset += os.write(descriptor, encoded[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "append_private_jsonl",
    "monitor_payload",
    "render_text",
    "resource_snapshot",
]
