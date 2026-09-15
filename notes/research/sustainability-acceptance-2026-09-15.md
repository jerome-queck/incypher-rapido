# Accelerated sustainability evidence — 2026-09-15

Status: strong accelerated evidence. This is **not** a 5.5-hour rehearsal and does not claim one.

## Exact-final-image useful work

One unattended, submission-disabled whole-catalogue run used
`rapido@sha256:e8c14d8e28ddfbefcc5cc96571e2d382eccfdc654f8140d0948ab10d95a28ebb`
with Daybreak/xhigh. It ran 1 hour 3 minutes 43 seconds, exited 0 without OOM/restart, qualified all
15 current practice challenges, skipped the one solved challenge, and completed 14 two-lane waves.

- All 28 lanes overlapped in pairs and used successful source-bound tools. The matrix covered static
  artifacts, assigned-authority HTTP, raw TCP, PoW/team-key handling, binary and archive analysis,
  DICOM, WAV/audio, native app-server inference, SQLite durability, and nine Board lifecycle cycles.
- Seven challenges reached two-lane candidate agreement and seven were truthfully unsolved. No
  challenge ended unsupported or error. Submissions and submission intents were zero.
- All nine target rows were receipt-bearing and `removed`; independent Board checks returned 404
  with no connection information. SQLite integrity was `ok` and no challenge/lane workspace content
  remained.
- Five-second samples peaked at about 216 MiB memory, 59/256 PIDs, and 1.73/8 CPUs. The state
  database was 122,880 bytes on a roughly 492-GiB filesystem.

## Exact-final-image signal and restart recovery

- During an active challenge-42 target and two admitted lanes, ordinary Docker SIGTERM exited 130
  in 2.59 seconds. Both attempts became `cancelled`, the run became `interrupted`, SQLite integrity
  remained `ok`, nested workspace content was removed, receipt-bound cleanup recorded the instance
  `removed`, and an independent Board GET returned 404. No submission occurred.
- A separate challenge-7 run was SIGKILLed after both lane directories existed. It exited 137 with
  `OOMKilled=false`. A fresh exact-image container on the same volume exited 0, recovered the old run
  and both attempts as `interrupted`, recorded one recovery event covering two attempts, removed
  stale workspace content, completed a fresh bounded wave, and retained SQLite integrity `ok`.
  No submission occurred.
- Rapido admits at most one active tool request per logical turn. Repeated cancellation drains the
  bounded worker before releasing admission. Deployment templates give the drain, 45-second dynamic
  cleanup, native teardown, and scheduling margin 180 seconds.

## Accelerated state/queue harness

Direct observation from `PYTHONPATH=. .venv/bin/python scripts/sustainability_acceptance.py
--cycles 96`:

- 96 measured cycles after three warmups; 768 bounded synthetic jobs; 96 durable interrupted-state
  recoveries; 1.151 seconds; no harness gate failures.
- Outcomes: 192 each cancelled, failed, timed out, and unsolved; peak active/queue size 2/2.
- File descriptors 7 → 7; asyncio tasks 1 → 1; threads 1 → 1.
- Traced heap 12,472 → 61,798 bytes; RSS high-water 37,076,992 → 37,519,360 bytes; temporary SQLite
  storage 57,344 → 270,336 bytes. Temporary storage was removed.
- The deliberately pessimistic arithmetic projects 3,409,466 cycles at twice observed synthetic
  throughput over 19,800 seconds. Its capacity status remains
  `not_assessed_no_host_quotas`: this projection is not a physical bound or workload forecast.

## Conservative 5.5-hour capacity projection

Treating the entire observed start-to-peak memory difference as monotonic growth, doubling that
slope, and extending it from 3,822.6 to 19,800 seconds gives `49.9 MiB + 2 × (215.8 - 49.9) MiB ×
(19,800 / 3,822.6) = 1,768.9 MiB`, or about 1.73 GiB—under 8% of the enforced
24-GiB limit. Applying the same deliberately pessimistic convention from zero to the final database
gives `2 × 122,880 bytes × (19,800 / 3,822.6) = 1,272,967 bytes`, or about 1.22 MiB, on the roughly
492-GiB state filesystem. PID and workspace measurements showed no monotonic growth: PIDs peaked at
59/256 and all per-challenge content was removed. These are capacity projections with safety
amplification, not workload forecasts.

## Evidence limits

No single container was run continuously for 5.5 hours. Disk-full, daemon failure, host reboot,
prolonged Board outage, auth expiry/refresh, and forced 24-GiB memory pressure were not physically
injected. Synthetic projection does not substitute for those tests. The real whole-catalogue run,
fault tests, bounded-growth projection, and synthetic cycles provide strong accelerated evidence for
the current 5.5-hour practice workload within the enforced limits.
