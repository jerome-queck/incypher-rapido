"""Network-free fixture rehearsal. No shell, external plugins, models, or live submissions."""
from __future__ import annotations

import asyncio
import base64
import binascii
import fcntl
import hashlib
import json
import math
import sqlite3
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

Operation = Literal["base64", "hex", "sha256"]
MAX_INPUT = 8192


def dispatch(operation: str, payload: str) -> bytes:
    """The entire toolbox: three bounded pure operations, no dynamic code execution."""
    if not isinstance(payload, str) or len(payload.encode("utf-8")) > MAX_INPUT:
        raise ValueError("payload must be text of at most 8192 UTF-8 bytes")
    try:
        if operation == "base64":
            return base64.b64decode(payload, validate=True)
        if operation == "hex":
            return bytes.fromhex(payload)
        if operation == "sha256":
            return hashlib.sha256(payload.encode("utf-8")).hexdigest().encode("ascii")
    except (binascii.Error, UnicodeError) as exc:
        raise ValueError("invalid encoded input") from exc
    raise ValueError("unsupported operation")


@dataclass(frozen=True)
class Job:
    id: str
    operation: Operation
    payload: str
    expected_sha256: str

    def __post_init__(self) -> None:
        if not self.id or len(self.id) > 64 or not self.id.isascii():
            raise ValueError("job id must be 1-64 ASCII characters")
        if self.operation not in ("base64", "hex", "sha256"):
            raise ValueError("unsupported operation")
        if len(self.payload.encode("utf-8")) > MAX_INPUT:
            raise ValueError("fixture input is too large")
        if len(self.expected_sha256) != 64 or any(
            c not in "0123456789abcdef" for c in self.expected_sha256
        ):
            raise ValueError("expected_sha256 must be a lowercase SHA-256 digest")

    @property
    def fingerprint(self) -> str:
        content = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(content.encode()).hexdigest()


def fixtures() -> list[Job]:
    """Known-answer toy data, deliberately unrelated to the official practice set."""
    return [
        Job("demo-base64", "base64", "aGVsbG8=",
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
        Job("demo-hex", "hex", "776f726c64",
            "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7"),
        # The expected output is the ASCII SHA-256 of an empty string.
        Job("demo-hash", "sha256", "",
            "cd372fb85148700fa88095e3492d3f9f5beb43e555e5ff26d95f5a6adc36f8e6"),
    ]


class Ledger:
    """One local runner per database; verified results survive process restarts."""

    def __init__(self, path: str | Path) -> None:
        self._lock = None
        self.db = None
        path = str(path)
        try:
            if path != ":memory:":
                Path(path).parent.mkdir(parents=True, exist_ok=True)
                self._lock = open(path + ".lock", "a+b")
                try:
                    fcntl.flock(self._lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise ValueError("another runner already holds this database") from exc
            self.db = sqlite3.connect(path, timeout=5)
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute(
                "CREATE TABLE IF NOT EXISTS results("
                "fingerprint TEXT PRIMARY KEY, job_id TEXT NOT NULL, "
                "status TEXT NOT NULL, elapsed_ms REAL NOT NULL)"
            )
            self.db.commit()
        except BaseException:
            self.close()
            raise

    def verified(self, fingerprint: str) -> bool:
        assert self.db is not None
        row = self.db.execute(
            "SELECT status FROM results WHERE fingerprint=?", (fingerprint,)
        ).fetchone()
        return row == ("verified",)

    def record(self, job: Job, status: str, elapsed_ms: float) -> dict:
        assert self.db is not None
        with self.db:
            self.db.execute(
                "INSERT INTO results VALUES(?,?,?,?) "
                "ON CONFLICT(fingerprint) DO UPDATE SET "
                "status=excluded.status, elapsed_ms=excluded.elapsed_ms",
                (job.fingerprint, job.id, status, elapsed_ms),
            )
        # Never retain decoded contents in the report or database.
        return {"job_id": job.id, "status": status, "elapsed_ms": round(elapsed_ms, 3)}

    def close(self) -> None:
        if self.db is not None:
            self.db.close()
            self.db = None
        if self._lock is not None:
            self._lock.close()
            self._lock = None

    def __enter__(self) -> Ledger:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


async def run_jobs(
    jobs: list[Job], ledger: Ledger, *, lanes: int = 2,
    deadline_seconds: float = 10.0, simulated_io_seconds: float = 0.05,
) -> dict:
    """Execute only the fixed pure toolbox; validate against local expected digests.

    Artificial delay exercises overlapping I/O waits. Timing is NOT CTF/model performance.
    Cancellation is cooperative; no subprocesses or threads are started.
    """
    if type(lanes) is not int or not 1 <= lanes <= 16:
        raise ValueError("lanes must be an integer from 1 to 16")
    if not math.isfinite(deadline_seconds) or not 0 < deadline_seconds <= 3600:
        raise ValueError("deadline must be finite and in (0, 3600]")
    if not math.isfinite(simulated_io_seconds) or not 0 <= simulated_io_seconds <= 5:
        raise ValueError("simulated I/O delay must be finite and in [0, 5]")
    if len(jobs) > 1000:
        raise ValueError("too many fixtures")
    unique = {job.fingerprint: job for job in jobs}
    queue: asyncio.Queue[Job] = asyncio.Queue()
    results: dict[str, dict] = {}
    active = peak = 0
    start = time.monotonic()
    for fingerprint, job in unique.items():
        if ledger.verified(fingerprint):
            results[fingerprint] = {
                "job_id": job.id, "status": "cached", "elapsed_ms": 0.0
            }
        else:
            queue.put_nowait(job)

    async def worker() -> None:
        nonlocal active, peak
        while True:
            try:
                job = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            began = time.monotonic()
            active += 1
            peak = max(peak, active)
            try:
                await asyncio.sleep(simulated_io_seconds)
                try:
                    output = dispatch(job.operation, job.payload)
                    status = ("verified" if hashlib.sha256(output).hexdigest()
                              == job.expected_sha256 else "incorrect")
                except ValueError:
                    status = "invalid_input"
                results[job.fingerprint] = ledger.record(
                    job, status, (time.monotonic() - began) * 1000
                )
            finally:
                active -= 1
                queue.task_done()

    def mark_remaining(status: str) -> None:
        for fingerprint, job in unique.items():
            if fingerprint not in results:
                results[fingerprint] = ledger.record(job, status, 0.0)

    try:
        async with asyncio.timeout(deadline_seconds):
            async with asyncio.TaskGroup() as group:
                for _ in range(lanes):
                    group.create_task(worker())
    except TimeoutError:
        mark_remaining("timed_out")
    except asyncio.CancelledError:
        mark_remaining("cancelled")
        raise
    return {
        "mode": "offline_fixture_rehearsal",
        "competition_ready": False,
        "model_calls": 0,
        "network_requests": 0,
        "live_submissions": 0,
        "simulated_io_seconds_per_job": simulated_io_seconds,
        "lanes": lanes,
        "max_active": peak,
        "wall_ms": round((time.monotonic() - start) * 1000, 3),
        "duplicate_inputs_removed": len(jobs) - len(unique),
        "results": [results[fingerprint] for fingerprint in unique],
    }
