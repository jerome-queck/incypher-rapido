"""Accelerated synthetic state/queue checks; never connects to Board or a model.

Run with the installed project: python scripts/sustainability_acceptance.py.
Only a newly created temporary directory is used. Projection is arithmetic for
this workload, not evidence of native/container or full-duration sustainability.
"""

from __future__ import annotations

import argparse
import asyncio
import gc
import json
import math
import os
import resource
import sys
import tempfile
import threading
import time
import tracemalloc
from collections import Counter
from pathlib import Path

from rapido.state import StateStore


def _fd_count() -> int | None:
    for path in (Path("/proc/self/fd"), Path("/dev/fd")):
        if path.is_dir():
            return len(os.listdir(path))
    return None


def sample(root: Path, cycle: int, started: float) -> dict[str, int | float | None]:
    """Sample after every cycle closes state, releases workers, and collects GC."""
    gc.collect()
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return {
        "cycle": cycle,
        "seconds": time.monotonic() - started,
        "heap_bytes": tracemalloc.get_traced_memory()[0],
        "rss_high_water_bytes": int(usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024)),
        "cpu_seconds": usage.ru_utime + usage.ru_stime,
        "fds": _fd_count(),
        "tasks": len(asyncio.all_tasks()),
        "threads": threading.active_count(),
        "storage_bytes": sum(path.stat().st_size for path in root.iterdir() if path.is_file()),
    }


async def _operation(kind: str) -> None:
    if kind == "failed":
        raise OSError("synthetic failure")
    if kind in {"timeout", "cancelled"}:
        await asyncio.Event().wait()
    await asyncio.sleep(0)


async def cycle(root: Path, index: int, workers: int, jobs: int) -> dict[str, int]:
    """Bounded workers drain faults, then reopen an intentionally unfinished run."""
    store = StateStore(root / "state.sqlite3")
    run_id = f"synthetic-{index}"
    counts: Counter[str] = Counter()
    queue: asyncio.Queue[int | None] = asyncio.Queue(maxsize=workers)
    active = 0
    peak_active = 0
    peak_queue = 0

    async def worker() -> None:
        nonlocal active, peak_active
        while True:
            number = await queue.get()
            try:
                if number is None:
                    return
                attempt = f"{run_id}-{number}"
                store.start_attempt(attempt, run_id, 1, number, "synthetic", "none")
                kind = ("unsolved", "failed", "timeout", "cancelled")[number % 4]
                active += 1
                peak_active = max(peak_active, active)
                operation = asyncio.create_task(_operation(kind))
                try:
                    if kind == "cancelled":
                        await asyncio.sleep(0)
                        operation.cancel()
                    await asyncio.wait_for(operation, timeout=0.005)
                    outcome = "unsolved"
                except TimeoutError:
                    outcome = "timeout"
                except OSError:
                    outcome = "failed"
                except asyncio.CancelledError:
                    # Only the deliberately cancelled operation is a test outcome.
                    # Cancellation of this worker must reach the outer cleanup.
                    current = asyncio.current_task()
                    if current is not None and current.cancelling():
                        raise
                    outcome = "cancelled"
                finally:
                    if not operation.done():
                        operation.cancel()
                    await asyncio.gather(operation, return_exceptions=True)
                    active -= 1
                store.finish_attempt(attempt, outcome, summary="synthetic fixture")
                counts[outcome] += 1
            finally:
                queue.task_done()

    tasks: list[asyncio.Task[None]] = []
    try:
        store.acquire_supervisor()
        store.start_run(run_id, {"synthetic_only": True})
        store.upsert_challenge(1, "Synthetic state fixture", "misc", "standard", 0)
        tasks = [asyncio.create_task(worker()) for _ in range(workers)]
        for number in range(jobs):
            await queue.put(number)
            peak_queue = max(peak_queue, queue.qsize())
        for _ in tasks:
            await queue.put(None)
        await asyncio.gather(*tasks)
        await queue.join()
        if active != 0 or sum(counts.values()) != jobs or queue.qsize():
            raise RuntimeError("synthetic worker accounting failed")
        store.set_challenge_status(1, "running")
        store.start_attempt(f"{run_id}-unfinished", run_id, 1, jobs, "synthetic", "none")
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        store.close()

    reopened = StateStore(root / "state.sqlite3")
    try:
        reopened.acquire_supervisor()
        recovered = reopened.recover_interrupted()
        if recovered != 1 or reopened.active_attempts():
            raise RuntimeError("synthetic restart left active or missing attempts")
        if reopened._connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise RuntimeError("synthetic SQLite integrity check failed")
        run_status = reopened._connection.execute(
            "SELECT status FROM runs WHERE id=?", (run_id,)
        ).fetchone()[0]
        if run_status != "interrupted" or reopened.recover_interrupted() != 0:
            raise RuntimeError("synthetic recovery was not durable and idempotent")
    finally:
        reopened.close()
    return {**counts, "recovered": recovered, "peak_active": peak_active, "peak_queue": peak_queue}


def assess(
    samples: list[dict[str, int | float | None]], projection_seconds: float
) -> dict[str, object]:
    """Allow bounded sampling noise; reject persistent resource counts and growth."""
    if len(samples) < 9 or projection_seconds <= 0 or not math.isfinite(projection_seconds):
        raise ValueError("need at least nine samples and a finite positive projection")
    first, last = samples[0], samples[-1]
    midpoint = len(samples) // 2
    middle = samples[midpoint]
    steps = int(last["cycle"]) - int(first["cycle"])
    duration = float(last["seconds"]) - float(first["seconds"])
    if steps <= 0 or duration <= 0:
        raise ValueError("sample cycle and time span must be positive")
    failures: list[str] = []
    growth: dict[str, object] = {}
    # DB page allocation and allocator high-water marks require explicit slack.
    limits = {
        "heap_bytes": (512 * 1024, 2048, 4096),
        "rss_high_water_bytes": (16 * 1024 * 1024, 128 * 1024, 256 * 1024),
        "storage_bytes": (None, 64 * 1024, 8192),
    }
    projection_cycles = math.ceil(projection_seconds * steps / duration * 2)
    for name, (total_limit, slope_limit, noise) in limits.items():
        baseline = int(first[name])
        delta = int(last[name]) - baseline
        early = (int(middle[name]) - baseline) / midpoint
        late = (int(last[name]) - int(middle[name])) / (len(samples) - 1 - midpoint)
        slope = max(0.0, early, late, delta / steps)
        peak_delta = max(int(row[name]) for row in samples) - baseline
        if total_limit is not None and peak_delta > total_limit:
            failures.append(f"{name}: retained growth exceeded {total_limit} bytes")
        if slope > slope_limit:
            failures.append(f"{name}: growth exceeded {slope_limit} bytes/cycle")
        if late > max(0.0, early) * 2 + noise:
            failures.append(f"{name}: late growth accelerated beyond noise allowance")
        growth[name] = {
            "delta": delta,
            "peak_delta": peak_delta,
            "early_bytes_per_cycle": early,
            "late_bytes_per_cycle": late,
            "conservative_bytes_per_cycle": slope,
            "projected_bytes": max(int(row[name]) for row in samples)
            + math.ceil((slope + noise) * projection_cycles),
            "noise_allowance_bytes_per_cycle": noise,
        }
    for name in ("fds", "tasks", "threads"):
        if any(row[name] is None for row in samples):
            failures.append(f"{name}: sampler unavailable")
        elif any(int(row[name]) > int(first[name]) for row in samples[1:]):
            failures.append(f"{name}: retained count increased after cycle cleanup")
    return {
        "status": "failed" if failures else "passed",
        "failures": failures,
        "growth": growth,
        "observed_cycles_per_second": steps / duration,
        "projection_seconds": projection_seconds,
        "projection_cycles_at_twice_observed_rate": projection_cycles,
        "projection_capacity_status": "not_assessed_no_host_quotas",
        "cpu_seconds_delta": float(last["cpu_seconds"]) - float(first["cpu_seconds"]),
    }


async def run(
    *, cycles: int = 48, workers: int = 2, jobs: int = 8, projection_seconds: float = 19800
) -> dict[str, object]:
    if not 12 <= cycles <= 1000 or not 1 <= workers <= 16 or not 4 <= jobs <= 256:
        raise ValueError("cycles must be 12..1000, workers 1..16, jobs 4..256")
    if not 0 < projection_seconds <= 31_536_000 or not math.isfinite(projection_seconds):
        raise ValueError("projection_seconds must be finite and within one year")
    if tracemalloc.is_tracing():
        raise RuntimeError("run harness in a fresh process without existing tracemalloc")
    tracemalloc.start()
    started = time.monotonic()
    samples: list[dict[str, int | float | None]] = []
    outcomes: Counter[str] = Counter()
    peaks = {"peak_active": 0, "peak_queue": 0}
    try:
        with tempfile.TemporaryDirectory(prefix="rapido-synthetic-sustainability-") as directory:
            root = Path(directory)
            async with asyncio.timeout(60):
                # Warm SQLite, asyncio, tracing and the sample collector before baseline.
                for index in range(3):
                    await cycle(root, index, workers, jobs)
                    sample(root, index, started)
                samples.append(sample(root, 0, started))
                for index in range(1, cycles + 1):
                    result = await cycle(root, index + 2, workers, jobs)
                    for key, value in peaks.items():
                        peaks[key] = max(value, result.pop(key))
                    outcomes.update(result)
                    samples.append(sample(root, index, started))
            report = assess(samples, projection_seconds)
    finally:
        tracemalloc.stop()
    return {
        **report,
        "scope": "synthetic StateStore and local asyncio queue only",
        "limitations": [
            "No Board, model, native app-server, container, credentials or network used.",
            "Reopen unfinished state simulates interrupted bookkeeping; no SIGKILL/SIGTERM tested.",
            "RSS is process lifetime high-water; current RSS and descendant processes not measured.",
            "Growth gates have explicit noise allowances; small/slow leaks may remain undetected.",
            (
                "Heap samples include this harness's retained telemetry; noise slack is extrapolated "
                "per cycle, making projected resource demand deliberately pessimistic."
            ),
            (
                "Projection uses half-window slopes plus slack and twice observed synthetic throughput; "
                "not a physical upper bound, host quota check, or full-duration/native workload proof."
            ),
            "Native home, container logs, production queue and filesystem-full behavior not tested.",
        ],
        "cycles": cycles,
        "warmup_cycles": 3,
        "workers": workers,
        "jobs_per_cycle": jobs,
        "outcomes": dict(outcomes),
        **peaks,
        "elapsed_seconds": time.monotonic() - started,
        "samples": samples,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycles", type=int, default=48)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--projection-seconds", type=float, default=19800)
    args = parser.parse_args()
    try:
        report = asyncio.run(run(**vars(args)))
    except (ValueError, RuntimeError, OSError, TimeoutError) as exc:
        # Fixed synthetic messages only; never echo environment or private paths.
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__}))
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
