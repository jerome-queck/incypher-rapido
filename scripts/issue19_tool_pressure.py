"""Offline final-image resource and containment pressure gate for issue 19.

Run only in a fresh hardened Rapido container. No inference, Board, auth, or
network work occurs. Tool logs and fixture contents are never emitted.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import mmap
import os
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import wave
import zlib
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PROTOCOL_ID = "issue19-tool-pressure-v1"
MIB = 1024 * 1024
GIB = 1024 * MIB
SAMPLE_SECONDS = 0.1
OUTER_SECONDS = 20 * 60
SHELL_SECONDS = 180
EXPECTED_LIMITS = {
    "cpu_cores": 12.0,
    "memory_bytes": 24 * GIB,
    "swap_bytes": 0,
    "pids": 256,
    "uid": 10001,
}
NORMAL_MEMORY_LIMIT = 18 * GIB
NORMAL_PID_LIMIT = 192
PID_PHASE_LIMIT = 208
HARD_MEMORY_LIMIT = int(21.6 * GIB)
HARD_PID_LIMIT = 224
BALLAST_BYTES = 512 * MIB
MEMORY_PER_WORKER = 1792 * MIB
MEMORY_MIN_PER_WORKER = int(1.65 * GIB)
ADVERSARIAL_GROUP_MEMORY = int(2.25 * GIB)
ANALYSIS_DIRECTORY = "rapido-analysis"


def _resource_envelope_matches(limits: dict[str, Any]) -> bool:
    return (
        abs(limits["cpu_cores"] - EXPECTED_LIMITS["cpu_cores"]) < 1e-9
        and limits["memory_max"] == EXPECTED_LIMITS["memory_bytes"]
        and limits["memory_swap_max"] == EXPECTED_LIMITS["swap_bytes"]
        and limits["pids_max"] == EXPECTED_LIMITS["pids"]
        and limits["uid"] == EXPECTED_LIMITS["uid"]
    )


def _mixed_cpu_matches(profile: int, peak: float) -> bool:
    return 0.5 * profile <= peak <= EXPECTED_LIMITS["cpu_cores"] + 0.25


def _pid_phase_within_global_fence(samples: dict[str, Any]) -> bool:
    return samples.get("pids_current_peak", HARD_PID_LIMIT) <= NORMAL_PID_LIMIT


def _pid_phase_evidence(
    result: dict[str, Any],
    samples: dict[str, Any],
    events: dict[str, int],
    groups_gone: bool,
) -> dict[str, Any]:
    return {
        "error": result.get("error_code"),
        "sources_unchanged": result.get("sources_unchanged"),
        "groups_gone": groups_gone,
        "pids_current_peak": samples.get("pids_current_peak"),
        "tracked_group_tasks_peak": samples.get("tracked_group_tasks_peak"),
        "pids_max_delta": events.get("pids_events.max", 0),
    }


class PreconditionError(RuntimeError):
    """The exact native-container protocol cannot run."""


class OuterDeadline(RuntimeError):
    """The harness exceeded its fixed wall-clock budget."""


def _round(value: float) -> float:
    return round(value, 3)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_hash(values: dict[str, str]) -> str:
    payload = json.dumps(values, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(payload).hexdigest()


def _source_hashes(root: Path, names: list[str]) -> tuple[str, dict[str, str]]:
    values = {name: _sha256(root / name) for name in sorted(set(names))}
    return _canonical_hash(values), values


def _fd_count() -> int | None:
    try:
        return len(list(Path("/proc/self/fd").iterdir()))
    except OSError:
        return None


def _task_count(pid: int | None = None) -> int:
    try:
        return len(list(Path(f"/proc/{pid or os.getpid()}/task").iterdir()))
    except OSError:
        return threading.active_count() if pid in {None, os.getpid()} else 0


def _proc_stat(pid: int) -> dict[str, Any] | None:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
        close = raw.rfind(")")
        if close < 0:
            return None
        fields = raw[close + 2 :].split()
        return {
            "pid": pid,
            "comm": raw[raw.find("(") + 1 : close],
            "ppid": int(fields[1]),
            "pgrp": int(fields[2]),
            "cpu_ticks": int(fields[11]) + int(fields[12]),
        }
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError):
        return None


def _proc_rss_kib(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text(encoding="ascii").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError, IndexError):
        pass
    return 0


def _scan_proc() -> dict[int, dict[str, Any]]:
    records: dict[int, dict[str, Any]] = {}
    try:
        entries = list(Path("/proc").iterdir())
    except OSError:
        return records
    for entry in entries:
        if not entry.name.isdigit():
            continue
        record = _proc_stat(int(entry.name))
        if record is None:
            continue
        try:
            record["tasks"] = _task_count(record["pid"])
        except OSError:
            record["tasks"] = 0
        record["rss_kib"] = _proc_rss_kib(record["pid"])
        records[record["pid"]] = record
    return records


def _direct_children() -> dict[str, int]:
    counts: Counter[str] = Counter()
    for record in _scan_proc().values():
        if record["ppid"] == os.getpid():
            counts[record["comm"]] += 1
    return dict(sorted(counts.items()))


def _census() -> dict[str, Any]:
    return {
        "fds": _fd_count(),
        "threads": _task_count(),
        "direct_children": _direct_children(),
    }


def _parse_kv(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].lstrip("-").isdigit():
            values[parts[0]] = int(parts[1])
    return values


def _pressure(path: Path) -> dict[str, int]:
    values: dict[str, int] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        parts = line.split()
        for item in parts[1:]:
            key, separator, value = item.partition("=")
            if separator and key == "total":
                values[f"{parts[0]}_total"] = int(value)
    return values


def _io_totals(path: Path) -> dict[str, int]:
    totals: Counter[str] = Counter()
    for line in path.read_text(encoding="ascii").splitlines():
        for item in line.split()[1:]:
            key, separator, value = item.partition("=")
            if separator and value.isdigit():
                totals[key] += int(value)
    return dict(sorted(totals.items()))


class Cgroup:
    """Read the current cgroup-v2 envelope and counters."""

    def __init__(self) -> None:
        if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
            raise PreconditionError("Linux cgroup v2 is required")
        relative = "/"
        for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
            if line.startswith("0::"):
                relative = line[3:] or "/"
                break
        mounted = Path("/sys/fs/cgroup")
        candidate = mounted / relative.lstrip("/")
        self.root = candidate if (candidate / "cgroup.procs").exists() else mounted

    def text(self, name: str) -> str:
        return (self.root / name).read_text(encoding="ascii").strip()

    def integer(self, name: str) -> int:
        value = self.text(name)
        if value == "max":
            raise PreconditionError(f"{name} must be finite")
        return int(value)

    def limits(self) -> dict[str, Any]:
        quota_text, period_text = self.text("cpu.max").split()
        if quota_text == "max":
            raise PreconditionError("cpu.max must be finite")
        quota, period = int(quota_text), int(period_text)
        return {
            "cpu_max": self.text("cpu.max"),
            "cpu_cores": quota / period,
            "memory_max": self.integer("memory.max"),
            "memory_swap_max": self.integer("memory.swap.max"),
            "pids_max": self.integer("pids.max"),
            "uid": os.getuid(),
        }

    def snapshot(self) -> dict[str, Any]:
        memory_stat = _parse_kv(self.root / "memory.stat")
        return {
            "memory_current": self.integer("memory.current"),
            "memory_peak": self.integer("memory.peak"),
            "memory_stat": {
                key: memory_stat.get(key, 0)
                for key in ("anon", "file", "file_mapped", "shmem", "kernel")
            },
            "memory_events": _parse_kv(self.root / "memory.events"),
            "memory_events_local": _parse_kv(self.root / "memory.events.local"),
            "pids_current": self.integer("pids.current"),
            "pids_peak": (
                self.integer("pids.peak") if (self.root / "pids.peak").exists() else None
            ),
            "pids_events": _parse_kv(self.root / "pids.events"),
            "cpu_stat": _parse_kv(self.root / "cpu.stat"),
            "cpu_pressure": _pressure(self.root / "cpu.pressure"),
            "memory_pressure": _pressure(self.root / "memory.pressure"),
            "io_stat": _io_totals(self.root / "io.stat"),
        }


def _event_delta(before: dict[str, Any], after: dict[str, Any]) -> dict[str, int]:
    values: dict[str, int] = {}
    for section in ("memory_events", "memory_events_local", "pids_events"):
        keys = set(before.get(section, {})) | set(after.get(section, {}))
        for key in sorted(keys):
            values[f"{section}.{key}"] = int(after.get(section, {}).get(key, 0)) - int(
                before.get(section, {}).get(key, 0)
            )
    return values


def _progress_stamp(path: Path) -> tuple[int, int]:
    newest = 0
    total = 0
    try:
        for index, entry in enumerate(path.rglob("*")):
            if index >= 2000:
                break
            try:
                metadata = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            newest = max(newest, metadata.st_mtime_ns)
            if entry.is_file():
                total += metadata.st_size
    except OSError:
        pass
    return newest, total


class Sampler:
    """Sample cgroup and tracked worker process groups every 100 ms."""

    def __init__(self, cgroup: Cgroup) -> None:
        self.cgroup = cgroup
        self.samples: list[dict[str, Any]] = []
        self.groups: dict[str, tuple[int, Path]] = {}
        self._known_pgids: set[int] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="pressure-sampler", daemon=True)
        self._last_progress_ns = 0
        self.errors: list[str] = []

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=3)

    def register(self, label: str, shell_pid: int, analysis: Path) -> int | None:
        record = _proc_stat(shell_pid)
        if record is None:
            return None
        with self._lock:
            self.groups[label] = (record["pgrp"], analysis)
            self._known_pgids.add(record["pgrp"])
        return int(record["pgrp"])

    def recorded_pgids(self) -> set[int]:
        with self._lock:
            return set(self._known_pgids)

    def unregister(self, labels: set[str]) -> None:
        with self._lock:
            for label in labels:
                self.groups.pop(label, None)

    def _run(self) -> None:
        while not self._stop.is_set():
            started = time.monotonic_ns()
            try:
                cgroup = self.cgroup.snapshot()
                processes = _scan_proc()
                with self._lock:
                    groups = dict(self.groups)
                progress_due = started - self._last_progress_ns >= 1_000_000_000
                group_values: dict[str, dict[str, Any]] = {}
                for label, (pgid, path) in groups.items():
                    members = [item for item in processes.values() if item["pgrp"] == pgid]
                    group_values[label] = {
                        "pgid": pgid,
                        "processes": len(members),
                        "tasks": sum(int(item["tasks"]) for item in members),
                        "rss_bytes": sum(int(item["rss_kib"]) for item in members) * 1024,
                        "cpu_ticks": sum(int(item["cpu_ticks"]) for item in members),
                        "comm_counts": dict(
                            sorted(Counter(item["comm"] for item in members).items())
                        ),
                        "progress": _progress_stamp(path) if progress_due and members else None,
                    }
                if progress_due:
                    self._last_progress_ns = started
                with self._lock:
                    self.samples.append(
                        {"monotonic_ns": started, "cgroup": cgroup, "groups": group_values}
                    )
            except Exception as exc:  # noqa: BLE001 - surfaced as a failed receipt gate
                self.errors.append(type(exc).__name__)
            delay = SAMPLE_SECONDS - (time.monotonic_ns() - started) / 1_000_000_000
            self._stop.wait(max(0.001, delay))

    def segment(self, started_ns: int, ended_ns: int) -> dict[str, Any]:
        with self._lock:
            samples = [
                value for value in self.samples if started_ns <= value["monotonic_ns"] <= ended_ns
            ]
        if not samples:
            return {"sample_count": 0}
        peak_cores = 0.0
        for end_index, end in enumerate(samples):
            for start in samples[: end_index + 1]:
                elapsed = (end["monotonic_ns"] - start["monotonic_ns"]) / 1_000_000_000
                if not 4.8 <= elapsed <= 5.3:
                    continue
                usage = end["cgroup"]["cpu_stat"].get("usage_usec", 0) - start["cgroup"][
                    "cpu_stat"
                ].get("usage_usec", 0)
                peak_cores = max(peak_cores, usage / (elapsed * 1_000_000))
        stalled: list[str] = []
        labels = {label for sample in samples for label in sample["groups"]}
        clock_ticks = os.sysconf("SC_CLK_TCK")
        for label in sorted(labels):
            active = [
                (sample["monotonic_ns"], sample["groups"][label])
                for sample in samples
                if sample["groups"].get(label, {}).get("tasks", 0) > 0
            ]
            for index, (end_ns, end_value) in enumerate(active):
                for start_ns, start_value in active[: index + 1]:
                    if end_ns - start_ns < 30_000_000_000:
                        continue
                    cpu_delta = (end_value["cpu_ticks"] - start_value["cpu_ticks"]) / clock_ticks
                    progress = [
                        value["progress"]
                        for sample_ns, value in active
                        if start_ns <= sample_ns <= end_ns and value["progress"] is not None
                    ]
                    if cpu_delta < 0.1 and len(set(progress)) <= 1:
                        stalled.append(label)
                    break
                if label in stalled:
                    break
        first, last = samples[0]["cgroup"], samples[-1]["cgroup"]
        return {
            "sample_count": len(samples),
            "memory_current_min": min(s["cgroup"]["memory_current"] for s in samples),
            "memory_current_peak": max(s["cgroup"]["memory_current"] for s in samples),
            "pids_current_min": min(s["cgroup"]["pids_current"] for s in samples),
            "pids_current_peak": max(s["cgroup"]["pids_current"] for s in samples),
            "tracked_group_rss_peak": max(
                [v["rss_bytes"] for s in samples for v in s["groups"].values()] or [0]
            ),
            "tracked_group_tasks_peak": max(
                [v["tasks"] for s in samples for v in s["groups"].values()] or [0]
            ),
            "cpu_cores_peak_5s": _round(peak_cores),
            "stalled_groups": sorted(set(stalled)),
            "event_deltas": _event_delta(first, last),
        }

    def global_summary(self) -> dict[str, Any]:
        with self._lock:
            samples = list(self.samples)
        if not samples:
            return {"sample_count": 0}
        return {
            "sample_count": len(samples),
            "memory_current": max(s["cgroup"]["memory_current"] for s in samples),
            "memory_reported": max(s["cgroup"]["memory_peak"] for s in samples),
            "pids_current": max(s["cgroup"]["pids_current"] for s in samples),
            "pids_reported": max(
                [s["cgroup"]["pids_peak"] for s in samples if s["cgroup"]["pids_peak"] is not None]
                or [0]
            ),
            "tracked_group_rss": max(
                [v["rss_bytes"] for s in samples for v in s["groups"].values()] or [0]
            ),
            "tracked_group_tasks": max(
                [v["tasks"] for s in samples for v in s["groups"].values()] or [0]
            ),
        }


def _png_fixture() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
        + chunk(b"IEND", b"")
    )


def _pcap_fixture() -> bytes:
    payload = b"GET / HTTP/1.0\r\n"
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ip_length = 20 + 20 + len(payload)
    ipv4 = struct.pack(
        ">BBHHHBBH4s4s",
        0x45,
        0,
        ip_length,
        0,
        0x4000,
        64,
        6,
        0,
        bytes((192, 0, 2, 1)),
        bytes((198, 51, 100, 2)),
    )
    tcp = struct.pack(">HHIIHHHH", 1234, 80, 0, 0, 0x5018, 4096, 0, 0)
    packet = ethernet + ipv4 + tcp + payload
    return (
        struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        + struct.pack("<IIII", 1, 0, len(packet), len(packet))
        + packet
    )


def _pdf_fixture() -> bytes:
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        3: (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
        ),
        4: b"<< /Length 30 >>\nstream\nBT /F1 12 Tf (pressure) Tj ET\nendstream",
        5: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    result = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number in range(1, 6):
        offsets.append(len(result))
        result.extend(f"{number} 0 obj\n".encode())
        result.extend(objects[number] + b"\nendobj\n")
    xref = len(result)
    result.extend(b"xref\n0 6\n0000000000 65535 f \n")
    for offset in offsets[1:]:
        result.extend(f"{offset:010d} 00000 n \n".encode())
    result.extend(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(result)


def _fixture_files(root: Path) -> None:
    root.mkdir(parents=True, mode=0o700)
    (root / "seed.txt").write_text("offline pressure fixture\n", encoding="utf-8")
    (root / "tiny.png").write_bytes(_png_fixture())
    (root / "fixture.pcap").write_bytes(_pcap_fixture())
    (root / "fixture.pdf").write_bytes(_pdf_fixture())
    (root / "opaque.bin").write_bytes(b"pressure\x00fixture\x00" * 128)
    (root / "tiny.c").write_text(
        '#include <stdio.h>\nint main(void){puts("toolchain-ok");return 0;}\n',
        encoding="utf-8",
    )
    (root / "angr.c").write_text(
        """#include <string.h>
#include <unistd.h>
__attribute__((noinline)) void win(void){ _exit(0); }
int main(void){ char b[16]; if(read(0,b,16)==16 && !memcmp(b,"PRESSURE-ANSWER!",16)) win(); return 1; }
""",
        encoding="utf-8",
    )
    methods = "\n".join(f"public static int method{i}(){{return {i};}}" for i in range(400))
    (root / "Bulk.java").write_text(f"public class Bulk{{{methods}}}\n", encoding="utf-8")
    matrix = []
    for row in range(96):
        matrix.append(
            " ".join(
                str(1000 + row if row == column else ((row * 17 + column * 31) % 7) - 3)
                for column in range(96)
            )
        )
    (root / "matrix.txt").write_text("\n".join(matrix) + "\n", encoding="utf-8")
    (root / "hashes.txt").write_text("5f4dcc3b5aa765d61d8327deb882cf99\n", encoding="ascii")
    (root / "words.txt").write_text("wrong\npassword\n", encoding="ascii")
    with wave.open(str(root / "fixture.wav"), "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8000)
        output.writeframes(b"\x00\x00" * 8000)
    filesystem = root / "fixture.ext2"
    with filesystem.open("wb") as output:
        output.truncate(4 * MIB)
    completed = subprocess.run(
        ("/usr/sbin/mke2fs", "-F", "-q", str(filesystem)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        raise PreconditionError("failed to create the offline ext2 fixture")


def _workloads() -> list[dict[str, Any]]:
    architecture = platform.machine().lower()
    qemu = "qemu-aarch64" if architecture in {"aarch64", "arm64"} else "qemu-x86_64"
    prefix = "set -euo pipefail; echo $$ > shell.pid; echo started > progress; sleep 5; "
    return [
        {
            "name": "ghidra",
            "sources": ["tiny.c"],
            "marker": "ghidra-ok",
            "command": prefix
            + "rm -rf ghidra-project tiny ghidra.log; gcc -O0 -fno-pie -no-pie ../tiny.c -o tiny; "
            + 'analyzeHeadless "$PWD" ghidra-project -import tiny -overwrite '
            + "-analysisTimeoutPerFile 60 -deleteProject >ghidra.log 2>&1; "
            + "test -s ghidra.log; echo ghidra-ok; echo done > done",
        },
        {
            "name": "jadx",
            "sources": ["Bulk.java"],
            "marker": "jadx-ok",
            "command": prefix
            + "rm -rf jadx-out Bulk.java Bulk.class bulk.jar; cp ../Bulk.java .; javac Bulk.java; "
            + "jar --create --file bulk.jar Bulk.class; jadx --threads-count 1 --output-dir jadx-out "
            + "bulk.jar >jadx.log 2>&1; grep -R -q 'return 399' jadx-out/sources; "
            + "echo jadx-ok; echo done > done",
        },
        {
            "name": "sage_lll",
            "sources": ["matrix.txt"],
            "marker": "sage-ok",
            "command": prefix
            + 'sage -c \'rows=[list(map(int,x.split())) for x in open("../matrix.txt")]; '
            + 'M=matrix(ZZ,rows); L=M.LLL(delta=.75); assert L.nrows()==96; print("sage-ok")\' '
            + ">sage.log 2>&1; grep -q sage-ok sage.log; echo sage-ok; echo done > done",
        },
        {
            "name": "angr",
            "sources": ["angr.c"],
            "marker": "angr-ok",
            "command": prefix
            + "rm -f angr-bin; gcc -O0 -fno-pie -no-pie ../angr.c -o angr-bin; "
            + "/opt/angr/bin/python - <<'PY' >angr.log 2>&1\n"
            + "import angr, claripy\n"
            + "p=angr.Project('./angr-bin', auto_load_libs=False)\n"
            + "data=claripy.BVS('stdin',128)\n"
            + "state=p.factory.full_init_state(stdin=angr.SimFileStream(name='stdin',content=data,has_end=True))\n"
            + "target=p.loader.main_object.get_symbol('win').rebased_addr\n"
            + "simgr=p.factory.simgr(state); simgr.explore(find=target,num_find=1)\n"
            + "assert simgr.found and simgr.found[0].solver.eval(data,cast_to=bytes)==b'PRESSURE-ANSWER!'\n"
            + "print('angr-ok')\nPY\n"
            + "grep -q angr-ok angr.log; echo angr-ok; echo done > done",
        },
        {
            "name": "hashcat",
            "sources": ["hashes.txt", "words.txt"],
            "marker": "hashcat-ok",
            "command": prefix
            + "rm -f hashcat.pot benchmark.log; hashcat -m 0 ../hashes.txt ../words.txt "
            + "--potfile-path hashcat.pot --quiet --force; hashcat -m 0 ../hashes.txt --show "
            + "--potfile-path hashcat.pot --quiet | grep -q ':password'; set +e; "
            + "hashcat -b -m 5600 --runtime=20 --force --machine-readable >benchmark.log 2>&1; "
            + "rc=$?; set -e; { [ $rc -eq 0 ] || [ $rc -eq 2 ]; }; test -s benchmark.log; "
            + "echo hashcat-ok; echo done > done",
        },
        {
            "name": "opencv",
            "sources": ["tiny.png"],
            "marker": "opencv-ok",
            "command": prefix
            + "python - <<'PY' >opencv.log 2>&1\n"
            + "import cv2, hashlib\n"
            + "cv2.setNumThreads(1)\n"
            + "image=cv2.imread('../tiny.png'); assert image is not None\n"
            + "image=cv2.resize(image,(8192,8192))\n"
            + "for _ in range(12): image=cv2.GaussianBlur(image,(7,7),1.2)\n"
            + "edges=cv2.Canny(image,50,150); assert edges.shape==(8192,8192)\n"
            + "assert cv2.imwrite('edges.png',edges) and len(hashlib.sha256(edges).digest())==32\n"
            + "print('opencv-ok')\nPY\n"
            + "grep -q opencv-ok opencv.log; echo opencv-ok; echo done > done",
        },
        {
            "name": "ffmpeg",
            "sources": ["tiny.png"],
            "marker": "ffmpeg-ok",
            "command": prefix
            + "ffmpeg -v error -loop 1 -i ../tiny.png -t 20 -r 30 "
            + "-vf scale=1920:1080 -threads 1 -f null -; "
            + "echo ffmpeg-ok; echo done > done",
        },
        {
            "name": "native_forensics",
            "sources": [
                "tiny.c",
                "fixture.pcap",
                "fixture.ext2",
                "fixture.pdf",
                "fixture.wav",
                "opaque.bin",
            ],
            "marker": "native-ok",
            "command": prefix
            + "rm -f tiny spectrogram.png; gcc -static -O0 ../tiny.c -o tiny; "
            + 'for i in $(seq 1 50); do test "$(tshark -r ../fixture.pcap -T fields '
            + '-e tcp.dstport)" = 80; done; fls ../fixture.ext2 >/dev/null; '
            + "qpdf --check ../fixture.pdf >/dev/null; binwalk ../opaque.bin >/dev/null; "
            + "sox ../fixture.wav -n spectrogram -o spectrogram.png; test -s spectrogram.png; "
            + "gdb -q -nx -batch -ex 'file ./tiny' -ex 'disassemble main' >gdb.log 2>&1; "
            + "grep -q 'Dump of assembler' gdb.log; "
            + f"{qemu} ./tiny | grep -q toolchain-ok; echo native-ok; echo done > done",
        },
    ]


class Harness:
    def __init__(self, profiles: list[int], rounds: int, output: Path) -> None:
        self.profiles = profiles
        self.rounds = rounds
        self.output = output
        self.started = time.monotonic()
        self.deadline = self.started + OUTER_SECONDS
        self.cgroup: Cgroup | None = None
        self.initial_cgroup: dict[str, Any] | None = None
        self.sampler: Sampler | None = None
        self.root: Path | None = None
        self.registries: list[Any] = []
        self.lanes: list[Path] = []
        self.executor: concurrent.futures.ThreadPoolExecutor | None = None
        self.padding_release = threading.Event()
        self.padding_threads: list[threading.Thread] = []
        self.ballast: mmap.mmap | None = None
        self.pending: set[concurrent.futures.Future[Any]] = set()
        self.gates: list[dict[str, Any]] = []
        self.result: dict[str, Any] = {
            "protocol_id": PROTOCOL_ID,
            "source_commit": os.environ.get("RAPIDO_SOURCE_COMMIT"),
            "image": os.environ.get("RAPIDO_IMAGE_DIGEST"),
            "arch": platform.machine().lower(),
            "started_at": datetime.now(UTC).isoformat(),
            "offline": True,
            "auth": False,
            "board": False,
            "network": False,
            "inference": False,
            "effective_model": None,
            "effective_reasoning_effort": None,
            "profiles": [],
            "gates": self.gates,
        }
        self.initial_census = _census()

    def gate(self, identifier: str, passed: bool, observed: Any, threshold: Any) -> bool:
        self.gates.append(
            {
                "id": identifier,
                "pass": bool(passed),
                "observed": observed,
                "threshold": threshold,
            }
        )
        return bool(passed)

    def check_deadline(self) -> None:
        if time.monotonic() >= self.deadline:
            raise OuterDeadline("20-minute harness deadline reached")

    def preconditions(self) -> None:
        source_commit = self.result.get("source_commit")
        image = self.result.get("image")
        if (
            not isinstance(source_commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", source_commit) is None
        ):
            raise PreconditionError("RAPIDO_SOURCE_COMMIT must be an exact lowercase commit SHA")
        if not isinstance(image, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", image) is None:
            raise PreconditionError("RAPIDO_IMAGE_DIGEST must be an exact lowercase image digest")
        if sys.platform != "linux":
            raise PreconditionError("native Linux is required")
        if self.profiles != [4, 6, 8] or self.rounds != 3:
            raise PreconditionError("registered protocol requires profiles 4,6,8 and 3 rounds")
        state = Path("/state")
        if not state.is_dir() or not os.access(state, os.W_OK):
            raise PreconditionError("/state must be writable")
        self.cgroup = Cgroup()
        limits = self.cgroup.limits()
        self.result["limits"] = limits
        if not _resource_envelope_matches(limits):
            raise PreconditionError(f"resource envelope mismatch: {limits!r}")
        self.initial_cgroup = self.cgroup.snapshot()

    def setup(self) -> None:
        assert self.cgroup is not None
        self.root = Path(tempfile.mkdtemp(prefix="issue19-pressure-", dir="/state"))
        for challenge in range(5):
            for lane in range(4):
                lane_root = self.root / f"challenge-{challenge + 1}" / f"lane-{lane + 1}"
                _fixture_files(lane_root)
                self.lanes.append(lane_root)
        import rapido.analysis_worker
        import rapido.analysis_worker_main
        import rapido.artifact_sandbox
        import rapido.tools
        from rapido.tools import ToolRegistry

        self.registries = [ToolRegistry(path) for path in self.lanes]
        source_files = [
            Path(__file__).resolve(),
            Path(rapido.analysis_worker.__file__).resolve(),
            Path(rapido.analysis_worker_main.__file__).resolve(),
            Path(rapido.artifact_sandbox.__file__).resolve(),
            Path(rapido.tools.__file__).resolve(),
        ]
        self.result["source_hashes"] = {
            path.name: _sha256(path) for path in source_files if path.is_file()
        }
        self.sampler = Sampler(self.cgroup)
        self.sampler.start()
        self.executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=20, thread_name_prefix="pressure-lane"
        )
        barrier = threading.Barrier(21)
        release = threading.Event()

        def bootstrap() -> None:
            barrier.wait(timeout=10)
            release.wait(timeout=10)

        boot = [self.executor.submit(bootstrap) for _ in range(20)]
        barrier.wait(timeout=10)
        release.set()
        for future in boot:
            future.result(timeout=10)
        self.ballast = mmap.mmap(-1, BALLAST_BYTES)
        for offset in range(0, BALLAST_BYTES, 4096):
            self.ballast[offset] = 1
        target = 92
        while self.cgroup.integer("pids.current") < target:
            thread = threading.Thread(
                target=self.padding_release.wait,
                name=f"pressure-padding-{len(self.padding_threads)}",
                daemon=True,
            )
            thread.start()
            self.padding_threads.append(thread)
            time.sleep(0.01)
            if self.cgroup.integer("pids.current") > target:
                raise PreconditionError("could not establish exact P20 PID baseline")
        if self.cgroup.integer("pids.current") != target:
            raise PreconditionError("could not establish exact P20 PID baseline")
        self.result["ballast"] = {
            "bytes": BALLAST_BYTES,
            "synthetic": True,
            "p20_baseline_pids": target,
            "padding_threads": len(self.padding_threads),
            "inference_claim": False,
        }

    def _prepare(self, lane: int, *names: str) -> Path:
        analysis = self.lanes[lane] / ANALYSIS_DIRECTORY
        analysis.mkdir(mode=0o700, exist_ok=True)
        for name in names:
            path = analysis / name
            try:
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
            except FileNotFoundError:
                pass
        return analysis

    def _call(
        self,
        lane: int,
        label: str,
        command: str,
        sources: list[str],
        marker: str | None,
        timeout: int,
    ) -> dict[str, Any]:
        from rapido.tools import ToolError

        pre, pre_values = _source_hashes(self.lanes[lane], sources)
        started_ns = time.monotonic_ns()
        result: dict[str, Any] | None = None
        error_code: str | None = None
        try:
            result = self.registries[lane].dispatch(
                "run_shell",
                {"command": command, "source_paths": sources, "timeout_seconds": timeout},
            )
        except ToolError as exc:
            error_code = exc.code
        except Exception as exc:  # noqa: BLE001 - class only; tool output remains private
            error_code = f"unexpected:{type(exc).__name__}"
        ended_ns = time.monotonic_ns()
        post, post_values = _source_hashes(self.lanes[lane], sources)
        stdout = result.get("stdout", "") if result else ""
        sandbox = result.get("sandbox", {}) if result else {}
        return {
            "label": label,
            "lane": lane,
            "started_ns": started_ns,
            "ended_ns": ended_ns,
            "elapsed_s": _round((ended_ns - started_ns) / 1_000_000_000),
            "error_code": error_code,
            "returncode": result.get("returncode") if result else None,
            "stop_reason": result.get("stop_reason") if result else None,
            "receipt": bool(marker and marker in stdout),
            "sandbox_enforced": bool(sandbox.get("enforced")),
            "network_denied": sandbox.get("network") == "denied" if result else None,
            "source_pre_sha256": pre,
            "source_post_sha256": post,
            "sources_unchanged": pre_values == post_values,
        }

    def _submit(self, *args: Any) -> concurrent.futures.Future[dict[str, Any]]:
        assert self.executor is not None
        future = self.executor.submit(self._call, *args)
        self.pending.add(future)
        future.add_done_callback(self.pending.discard)
        return future

    def _wait_markers(
        self,
        entries: list[tuple[str, Path, concurrent.futures.Future[Any]]],
        timeout: float,
    ) -> bool:
        deadline = min(time.monotonic() + timeout, self.deadline)
        remaining = {label: (path, future) for label, path, future in entries}
        while remaining and time.monotonic() < deadline:
            for label, (path, future) in list(remaining.items()):
                if path.is_file():
                    try:
                        pid = int(path.read_text(encoding="ascii").strip())
                    except (OSError, ValueError):
                        continue
                    if self.sampler is not None:
                        self.sampler.register(label, pid, path.parent)
                    del remaining[label]
                elif future.done():
                    return False
            time.sleep(0.05)
        return not remaining

    def _wait_results(
        self, futures: list[concurrent.futures.Future[dict[str, Any]]], timeout: float
    ) -> list[dict[str, Any]]:
        deadline = min(time.monotonic() + timeout, self.deadline)
        results: list[dict[str, Any]] = []
        for future in futures:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OuterDeadline("phase exceeded outer harness deadline")
            results.append(future.result(timeout=remaining))
        return results

    def _groups_gone(self, labels: set[str] | None = None, timeout: float = 5.0) -> bool:
        if self.sampler is None:
            return False
        with self.sampler._lock:
            groups = dict(self.sampler.groups)
        tracked = (
            self.sampler.recorded_pgids()
            if labels is None
            else {pgid for label, (pgid, _) in groups.items() if label in labels}
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            live = {record["pgrp"] for record in _scan_proc().values()}
            if tracked.isdisjoint(live):
                return True
            time.sleep(0.1)
        return False

    def admission(self) -> None:
        blocker_command = (
            "set -eu; echo $$ > shell.pid; : > ready; "
            "while [ ! -e release ]; do sleep 0.1; done; echo blocker-ok"
        )
        blockers: list[concurrent.futures.Future[dict[str, Any]]] = []
        blocker_markers = []
        blocker_labels = set()
        for lane in range(8):
            analysis = self._prepare(lane, "shell.pid", "ready", "release")
            label = f"admission-blocker-{lane}"
            blocker_labels.add(label)
            future = self._submit(
                lane,
                label,
                blocker_command,
                ["seed.txt"],
                "blocker-ok",
                30,
            )
            blockers.append(future)
            blocker_markers.append((label, analysis / "shell.pid", future))
        markers_ready = self._wait_markers(blocker_markers, 10)
        ready = markers_ready and all(
            (self.lanes[lane] / ANALYSIS_DIRECTORY / "ready").is_file() for lane in range(8)
        )
        overflow: list[concurrent.futures.Future[dict[str, Any]]] = []
        for lane in range(8, 20):
            self._prepare(lane, "overflow")
            overflow.append(
                self._submit(
                    lane,
                    f"admission-overflow-{lane}",
                    "printf overflow-ran > overflow",
                    ["seed.txt"],
                    None,
                    30,
                )
            )
        overflow_results = self._wait_results(overflow, 20)
        for lane in range(8):
            (self.lanes[lane] / ANALYSIS_DIRECTORY / "release").touch()
        blocker_results = self._wait_results(blockers, 10)
        changed = self._call(
            8,
            "admission-changed-followup",
            "echo changed-ok",
            ["seed.txt"],
            "changed-ok",
            30,
        )
        cleanup_ok = self._groups_gone(blocker_labels)
        self.sampler.unregister(blocker_labels)
        overflow_ok = all(
            value["error_code"] == "tool_busy"
            and 9.0 <= value["elapsed_s"] <= 12.5
            and value["sources_unchanged"]
            and not (self.lanes[value["lane"]] / ANALYSIS_DIRECTORY / "overflow").exists()
            for value in overflow_results
        )
        blocker_ok = all(
            value["error_code"] is None
            and value["returncode"] == 0
            and value["receipt"]
            and value["network_denied"]
            and value["sources_unchanged"]
            for value in blocker_results
        )
        changed_ok = (
            changed["error_code"] is None
            and changed["returncode"] == 0
            and changed["receipt"]
            and changed["sources_unchanged"]
            and changed["elapsed_s"] < 2.0
        )
        admission_ok = ready and overflow_ok and blocker_ok and changed_ok and cleanup_ok
        self.result["admission"] = {
            "challenges": 5,
            "lanes_per_challenge": 4,
            "callers": 20,
            "analysis_slots": 8,
            "blockers_ready": ready,
            "overflow": overflow_results,
            "blockers": blocker_results,
            "changed_followup": changed,
            "cleanup_ok": cleanup_ok,
            "ok": admission_ok,
        }
        self.gate(
            "p20_admission",
            admission_ok,
            {"overflow_tool_busy": sum(v["error_code"] == "tool_busy" for v in overflow_results)},
            {"overflow_tool_busy": 12, "latency_s": [9.0, 12.5], "changed_s_lt": 2.0},
        )

    def _round_indices(self, profile: int, round_index: int) -> list[int]:
        if profile == 4:
            return [0, 1, 2, 3] if round_index in {0, 2} else [4, 5, 6, 7]
        start = (round_index * 2) % 8
        values = [(start + offset) % 8 for offset in range(profile)]
        if round_index == 2:
            values = [0, 1, 2, 3] + [value for value in values if value not in {0, 1, 2, 3}]
        return values[:profile]

    def mixed_round(self, profile: int, round_index: int) -> dict[str, Any]:
        assert self.sampler is not None
        workloads = _workloads()
        indices = self._round_indices(profile, round_index)
        futures: list[concurrent.futures.Future[dict[str, Any]]] = []
        markers = []
        labels = set()
        started_ns = time.monotonic_ns()
        for lane, workload_index in enumerate(indices):
            workload = workloads[workload_index]
            analysis = self._prepare(lane, "shell.pid", "progress", "done")
            label = f"p{profile}-r{round_index + 1}-{workload['name']}"
            labels.add(label)
            future = self._submit(
                lane,
                label,
                workload["command"],
                workload["sources"],
                workload["marker"],
                SHELL_SECONDS,
            )
            futures.append(future)
            markers.append((label, analysis / "shell.pid", future))
        marker_ok = self._wait_markers(markers, 15)
        calls = self._wait_results(futures, SHELL_SECONDS + 5)
        ended_ns = time.monotonic_ns()
        cleanup_ok = self._groups_gone(labels)
        summary = self.sampler.segment(started_ns, ended_ns)
        self.sampler.unregister(labels)
        overlap_s = max(
            0.0,
            (
                min(value["ended_ns"] for value in calls)
                - max(value["started_ns"] for value in calls)
            )
            / 1_000_000_000,
        )
        calls_ok = all(
            value["error_code"] is None
            and value["returncode"] == 0
            and value["stop_reason"] is None
            and value["receipt"]
            and value["sandbox_enforced"]
            and value["network_denied"]
            and value["sources_unchanged"]
            and value["elapsed_s"] <= SHELL_SECONDS
            for value in calls
        )
        cpu_ok = _mixed_cpu_matches(profile, summary.get("cpu_cores_peak_5s", 0))
        resource_ok = (
            summary.get("memory_current_peak", HARD_MEMORY_LIMIT) <= NORMAL_MEMORY_LIMIT
            and summary.get("pids_current_peak", HARD_PID_LIMIT) <= NORMAL_PID_LIMIT
        )
        ok = (
            marker_ok
            and calls_ok
            and cleanup_ok
            and overlap_s >= 5.0
            and cpu_ok
            and resource_ok
            and not any(summary.get("event_deltas", {}).values())
            and not summary.get("stalled_groups")
        )
        return {
            "round": round_index + 1,
            "workloads": [workloads[index]["name"] for index in indices],
            "overlap_s": _round(overlap_s),
            "markers_ready": marker_ok,
            "calls": calls,
            "samples": summary,
            "cleanup_ok": cleanup_ok,
            "ok": ok,
        }

    def _held_phase(
        self,
        profile: int,
        kind: str,
        command: str,
        ready_name: str,
        release_name: str,
        marker: str,
    ) -> dict[str, Any]:
        assert self.sampler is not None and self.cgroup is not None
        baseline = self.cgroup.snapshot()
        started_ns = time.monotonic_ns()
        futures = []
        markers = []
        labels = set()
        ready_paths = []
        release_paths = []
        for lane in range(profile):
            analysis = self._prepare(lane, "shell.pid", ready_name, release_name)
            label = f"p{profile}-{kind}-{lane}"
            labels.add(label)
            future = self._submit(lane, label, command, ["seed.txt"], marker, SHELL_SECONDS)
            futures.append(future)
            markers.append((label, analysis / "shell.pid", future))
            ready_paths.append(analysis / ready_name)
            release_paths.append(analysis / release_name)
        marker_ok = self._wait_markers(markers, 15)
        deadline = min(time.monotonic() + 120, self.deadline)
        ready = False
        try:
            while time.monotonic() < deadline:
                if all(path.is_file() for path in ready_paths):
                    ready = True
                    break
                if any(future.done() for future in futures):
                    break
                time.sleep(0.1)
            if ready:
                time.sleep(15)
        finally:
            for path in release_paths:
                path.touch()
        calls = self._wait_results(futures, SHELL_SECONDS + 5)
        ended_ns = time.monotonic_ns()
        cleanup_ok = self._groups_gone(labels)
        summary = self.sampler.segment(started_ns, ended_ns)
        self.sampler.unregister(labels)
        calls_ok = all(
            value["error_code"] is None
            and value["returncode"] == 0
            and value["receipt"]
            and value["network_denied"]
            and value["sources_unchanged"]
            for value in calls
        )
        current = self.cgroup.snapshot()
        pid_recovered = current["pids_current"] <= baseline["pids_current"] + 2
        anon_deadline = time.monotonic() + 30
        while (
            current["memory_stat"]["anon"] > baseline["memory_stat"]["anon"] + 256 * MIB
            and time.monotonic() < anon_deadline
        ):
            time.sleep(0.25)
            current = self.cgroup.snapshot()
        anon_recovered = (
            current["memory_stat"]["anon"] <= baseline["memory_stat"]["anon"] + 256 * MIB
        )
        if kind == "memory":
            pressure_ok = (
                summary.get("memory_current_peak", 0) - baseline["memory_current"]
                >= MEMORY_MIN_PER_WORKER * profile
                and summary.get("memory_current_peak", HARD_MEMORY_LIMIT) <= NORMAL_MEMORY_LIMIT
            )
        else:
            pressure_ok = summary.get("pids_current_peak", HARD_PID_LIMIT) <= PID_PHASE_LIMIT
        ok = (
            marker_ok
            and ready
            and calls_ok
            and cleanup_ok
            and pid_recovered
            and anon_recovered
            and pressure_ok
            and not any(summary.get("event_deltas", {}).values())
        )
        return {
            "ready": ready,
            "markers_ready": marker_ok,
            "calls": calls,
            "samples": summary,
            "baseline": {
                "memory_current": baseline["memory_current"],
                "memory_anon": baseline["memory_stat"]["anon"],
                "pids_current": baseline["pids_current"],
            },
            "cleanup": {
                "groups_gone": cleanup_ok,
                "pids_recovered": pid_recovered,
                "anon_recovered": anon_recovered,
            },
            "ok": ok,
        }

    def profile(self, value: int) -> dict[str, Any]:
        rounds = [self.mixed_round(value, index) for index in range(self.rounds)]
        memory_command = f"""set -euo pipefail
echo $$ > shell.pid
python - <<'PY'
import mmap, pathlib, time
size={MEMORY_PER_WORKER}
memory=mmap.mmap(-1,size)
for offset in range(0,size,4096): memory[offset]=1
pathlib.Path('mem.ready').touch()
while not pathlib.Path('mem.release').exists(): time.sleep(.05)
memory.close()
print('memory-ok')
PY
"""
        pid_command = """set -euo pipefail
echo $$ > shell.pid
pids=""
for i in $(seq 1 8); do sleep 30 & pids="$pids $!"; done
touch pid.ready
while [ ! -e pid.release ]; do sleep 0.1; done
wait $pids
echo pid-ok
"""
        memory_phase = self._held_phase(
            value, "memory", memory_command, "mem.ready", "mem.release", "memory-ok"
        )
        pid_phase = self._held_phase(
            value, "pid", pid_command, "pid.ready", "pid.release", "pid-ok"
        )
        ok = all(item["ok"] for item in rounds) and memory_phase["ok"] and pid_phase["ok"]
        record = {
            "concurrency": value,
            "rounds": rounds,
            "memory_phase": memory_phase,
            "pid_phase": pid_phase,
            "selected": False,
            "ok": ok,
        }
        self.gate(
            f"profile_{value}",
            ok,
            {
                "mixed_rounds_passed": sum(item["ok"] for item in rounds),
                "memory_phase": memory_phase["ok"],
                "pid_phase": pid_phase["ok"],
            },
            {"mixed_rounds": 3, "memory_phase": True, "pid_phase": True},
        )
        return record

    def adversarial(self) -> None:
        assert self.sampler is not None and self.cgroup is not None
        virtual_command = """set -euo pipefail
echo $$ > shell.pid
python - <<'PY'
import mmap
value=mmap.mmap(-1,4*1024*1024*1024)
value[0]=1
value[-1]=1
value.close()
print('virtual-address-ok')
PY
"""
        virtual_result = self._call(
            0,
            "virtual-address-reservation",
            virtual_command,
            ["seed.txt"],
            "virtual-address-ok",
            60,
        )
        virtual_ok = (
            virtual_result["error_code"] is None
            and virtual_result["returncode"] == 0
            and virtual_result["receipt"]
            and virtual_result["network_denied"]
        )
        memory_command = """set -euo pipefail
echo $$ > shell.pid
for i in 1 2 3 4; do
  python -c 'import mmap,time; m=mmap.mmap(-1,768*1024*1024); [m.__setitem__(x,1) for x in range(0,768*1024*1024,4096)]; time.sleep(120)' &
done
wait
echo memory-tree-unsafe
"""
        memory_label = "adversarial-memory-tree"
        memory_analysis = self._prepare(1, "shell.pid")
        memory_before = self.cgroup.snapshot()
        memory_started = time.monotonic_ns()
        memory_future = self._submit(
            1, memory_label, memory_command, ["seed.txt"], "memory-tree-unsafe", 60
        )
        self._wait_markers([(memory_label, memory_analysis / "shell.pid", memory_future)], 10)
        memory_result = self._wait_results([memory_future], 70)[0]
        memory_ended = time.monotonic_ns()
        memory_after = self.cgroup.snapshot()
        memory_samples = self.sampler.segment(memory_started, memory_ended)
        memory_events = _event_delta(memory_before, memory_after)
        memory_gone = self._groups_gone({memory_label})
        self.sampler.unregister({memory_label})
        memory_ok = (
            memory_result["error_code"] == "resource_limit"
            and memory_result["sources_unchanged"]
            and memory_gone
            and memory_samples.get("tracked_group_rss_peak", ADVERSARIAL_GROUP_MEMORY + 1)
            <= ADVERSARIAL_GROUP_MEMORY
            and not any(memory_events.values())
        )
        pid_command = """set -euo pipefail
echo $$ > shell.pid
for i in $(seq 1 80); do sleep 120 & done
touch pid-tree.ready
wait
echo pid-tree-unsafe
"""
        pid_label = "adversarial-pid-tree"
        pid_analysis = self._prepare(2, "shell.pid", "pid-tree.ready")
        pid_before = self.cgroup.snapshot()
        pid_started = time.monotonic_ns()
        pid_future = self._submit(2, pid_label, pid_command, ["seed.txt"], "pid-tree-unsafe", 60)
        self._wait_markers([(pid_label, pid_analysis / "shell.pid", pid_future)], 10)
        pid_result = self._wait_results([pid_future], 70)[0]
        pid_ended = time.monotonic_ns()
        pid_after = self.cgroup.snapshot()
        pid_samples = self.sampler.segment(pid_started, pid_ended)
        pid_events = _event_delta(pid_before, pid_after)
        pid_gone = self._groups_gone({pid_label})
        self.sampler.unregister({pid_label})
        pid_ok = (
            pid_result["error_code"] == "resource_limit"
            and pid_result["sources_unchanged"]
            and pid_gone
            and _pid_phase_within_global_fence(pid_samples)
            and pid_events.get("pids_events.max", 0) == 0
        )
        self.result["adversarial"] = {
            "virtual_address": {"call": virtual_result, "ok": virtual_ok},
            "memory_tree": {
                "call": memory_result,
                "samples": memory_samples,
                "event_deltas": memory_events,
                "groups_gone": memory_gone,
                "ok": memory_ok,
            },
            "pid_tree": {
                "call": pid_result,
                "samples": pid_samples,
                "event_deltas": pid_events,
                "groups_gone": pid_gone,
                "ok": pid_ok,
            },
        }
        self.gate(
            "virtual_address_reservation",
            virtual_ok,
            virtual_result["receipt"],
            True,
        )
        self.gate(
            "adversarial_memory_tree",
            memory_ok,
            {
                "error": memory_result["error_code"],
                "rss_peak": memory_samples.get("tracked_group_rss_peak"),
                "event_deltas": memory_events,
            },
            {"error": "resource_limit", "rss_peak_lte": ADVERSARIAL_GROUP_MEMORY, "events": 0},
        )
        self.gate(
            "adversarial_pid_tree",
            pid_ok,
            _pid_phase_evidence(pid_result, pid_samples, pid_events, pid_gone),
            {
                "error": "resource_limit",
                "sources_unchanged": True,
                "groups_gone": True,
                "pids_current_peak": {"lte": NORMAL_PID_LIMIT},
                "pids_max_delta": 0,
            },
        )

    def run(self) -> None:
        self.preconditions()
        self.setup()
        self.admission()
        selected: int | None = None
        promotion_open = True
        for profile in self.profiles:
            self.check_deadline()
            record = self.profile(profile)
            self.result["profiles"].append(record)
            if promotion_open and record["ok"]:
                selected = profile
            else:
                promotion_open = False
        if selected is not None:
            for record in self.result["profiles"]:
                record["selected"] = record["concurrency"] == selected
        self.result["selection"] = {
            "initial_hypothesis": 4,
            "recommended_analysis_workers": selected,
            "five_challenge_p20_unchanged": True,
            "blocked": selected is None,
        }
        self.gate("profile_selection", selected is not None, selected, ">=4 contiguous pass")
        self.adversarial()

    def _release_everything(self) -> None:
        if self.root is None or not self.root.exists():
            return
        for name in ("release", "mem.release", "pid.release"):
            for analysis in self.root.glob(f"challenge-*/lane-*/{ANALYSIS_DIRECTORY}"):
                try:
                    (analysis / name).touch()
                except OSError:
                    pass

    def _kill_groups(self) -> None:
        if self.sampler is None:
            return
        own_group = os.getpgrp()
        for pgid in self.sampler.recorded_pgids():
            if pgid == own_group:
                continue
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    def cleanup(self) -> None:
        self._release_everything()
        self._kill_groups()
        for future in list(self.pending):
            future.cancel()
        if self.executor is not None:
            self.executor.shutdown(wait=True, cancel_futures=True)
        self.padding_release.set()
        for thread in self.padding_threads:
            thread.join(timeout=2)
        if self.ballast is not None:
            self.ballast.close()
        tracked_gone = self._groups_gone(timeout=5) if self.sampler is not None else True
        if self.sampler is not None:
            self.result["peaks"] = self.sampler.global_summary()
            self.sampler.stop()
        root_removed = True
        if self.root is not None:
            shutil.rmtree(self.root, ignore_errors=True)
            root_removed = not self.root.exists()
        final_census = _census()
        census_equal = final_census == self.initial_census
        self.result["cleanup"] = {
            "temporary_root_removed": root_removed,
            "tracked_groups_gone": tracked_gone,
            "baseline_census": self.initial_census,
            "final_census": final_census,
            "census_equal": census_equal,
        }
        self.gate(
            "cleanup",
            root_removed and tracked_gone and census_equal,
            self.result["cleanup"],
            "exact temporary root removed; tracked groups gone; controller census restored",
        )

    def finalize(self) -> None:
        assert self.cgroup is not None and self.initial_cgroup is not None
        final = self.cgroup.snapshot()
        deltas = _event_delta(self.initial_cgroup, final)
        self.result["event_deltas"] = deltas
        self.result["resource_deltas"] = {
            section: {
                key: int(final[section].get(key, 0)) - int(self.initial_cgroup[section].get(key, 0))
                for key in sorted(set(final[section]) | set(self.initial_cgroup[section]))
            }
            for section in (
                "cpu_stat",
                "cpu_pressure",
                "memory_pressure",
                "io_stat",
            )
        }
        peaks = self.result.get("peaks", {})
        watched_events = {
            "memory_events.oom",
            "memory_events.oom_kill",
            "memory_events.max",
            "memory_events_local.oom",
            "memory_events_local.oom_kill",
            "memory_events_local.max",
            "pids_events.max",
        }
        event_ok = not any(value for key, value in deltas.items() if key in watched_events)
        hard_ok = (
            peaks.get("memory_current", HARD_MEMORY_LIMIT) < HARD_MEMORY_LIMIT
            and peaks.get("pids_current", HARD_PID_LIMIT) < HARD_PID_LIMIT
        )
        self.gate("no_cgroup_limit_events", event_ok, deltas, 0)
        sampler_ok = self.sampler is not None and not self.sampler.errors
        self.gate(
            "sampler_integrity",
            sampler_ok,
            sorted(set(self.sampler.errors)) if self.sampler is not None else ["not_started"],
            [],
        )
        self.gate(
            "hard_resource_headroom",
            hard_ok,
            {
                "memory_peak": peaks.get("memory_current"),
                "pids_peak": peaks.get("pids_current"),
            },
            {"memory_lt": HARD_MEMORY_LIMIT, "pids_lt": HARD_PID_LIMIT},
        )
        self.result["elapsed_s"] = _round(time.monotonic() - self.started)
        self.result["ok"] = all(value["pass"] for value in self.gates)


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profiles", default="4,6,8")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--json", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        profiles = [int(value) for value in arguments.profiles.split(",")]
    except ValueError:
        profiles = []
    harness = Harness(profiles, arguments.rounds, arguments.json)
    exit_code = 1

    def deadline_signal(_signum: int, _frame: Any) -> None:
        raise OuterDeadline("hard outer watchdog fired")

    previous_alarm = None
    if hasattr(signal, "SIGALRM") and hasattr(signal, "setitimer"):
        previous_alarm = signal.signal(signal.SIGALRM, deadline_signal)
        signal.setitimer(signal.ITIMER_REAL, OUTER_SECONDS - 30)
    try:
        harness.run()
    except PreconditionError as exc:
        harness.result["precondition_error"] = str(exc)[:240]
        exit_code = 2
    except Exception as exc:  # noqa: BLE001 - bounded receipt, then deterministic cleanup
        harness.result["error"] = {
            "type": type(exc).__name__,
            "message": str(exc)[:240],
        }
    finally:
        if previous_alarm is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous_alarm)
        try:
            harness.cleanup()
        except Exception as exc:  # noqa: BLE001 - cleanup failure is a hard receipt gate
            harness.result["cleanup_error"] = {
                "type": type(exc).__name__,
                "message": str(exc)[:240],
            }
            harness.gate("cleanup_exception", False, type(exc).__name__, "no cleanup exception")
        if harness.cgroup is not None and harness.initial_cgroup is not None:
            try:
                harness.finalize()
            except Exception as exc:  # noqa: BLE001 - finalization failure is a hard gate
                harness.result["finalize_error"] = {
                    "type": type(exc).__name__,
                    "message": str(exc)[:240],
                }
                harness.result["ok"] = False
        else:
            harness.result["elapsed_s"] = _round(time.monotonic() - harness.started)
            harness.result["ok"] = False
        _write_json(arguments.json, harness.result)
    if exit_code != 2:
        exit_code = 0 if harness.result.get("ok") is True else 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
