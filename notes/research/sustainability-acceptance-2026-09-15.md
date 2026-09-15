# Accelerated sustainability evidence — 2026-09-15

Status: partial evidence only. This is not a 5.5-hour rehearsal and does not yet pass the
deployment sustainability gate.

## Synthetic state/queue run

Direct observation from `PYTHONPATH=. .venv/bin/python scripts/sustainability_acceptance.py
--cycles 96`:

- 96 measured cycles after 3 warmups; 768 bounded synthetic jobs; 96 durable interrupted-state
  recoveries; 1.291 seconds.
- Outcomes covered unsolved, failure, timeout, and cancellation on each cycle.
- File descriptors 7 → 7; asyncio tasks 1 → 1; threads 1 → 1.
- Traced heap 11,882 → 70,706 bytes; RSS high-water 36,651,008 → 37,224,448 bytes.
- Temporary SQLite storage 57,344 → 270,336 bytes. The temporary directory was removed.
- Conservative arithmetic projected 3,040,042 cycles at twice the observed synthetic rate over
  19,800 seconds, but capacity status was explicitly `not_assessed_no_host_quotas`.

The harness passed its retained-count, bounded-growth, nonlinear-growth, recovery, and integrity
checks. Projection slack deliberately amplifies sampling overhead; it is not a physical upper bound.

## Missing evidence

This run used no Board, model, network, app-server, container lifecycle, SIGTERM, real process
restart, disk pressure, or log-retention path. Real final-image waves, repeated dynamic lifecycle,
process/resource sampling, SIGTERM/restart, and capacity comparison remain required.
