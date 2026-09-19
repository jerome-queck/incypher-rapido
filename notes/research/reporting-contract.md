# Read-only reporting contract

`rapido.reporting` reconciles finalized SQLite archives without constructing `StateStore`, running
migrations, or importing private run values. It opens one regular database file with SQLite
`mode=ro`, `immutable=1`, and `query_only=ON`, then holds one read transaction. The input must
therefore be a finalized, checkpointed archive; any WAL, SHM, or rollback-journal sidecar fails
closed because immutable reads must not ignore uncheckpointed state.

The `rapido-reconciled-report-v1` document keeps five axes independent:

- externally accepted post-run correctness;
- distinct current-run Board `correct` tasks;
- `already_solved` submission identities, which are account history only;
- distinct runtime-current verification tasks;
- a separately versioned external evaluator result with named exclusion reasons.

The report never upgrades `already_solved`, equates runtime qualification with an external
evaluator, or reads `attempts.candidate` to find proof-backed proposals. Attempt/job and
submission/intent identities must reconcile in both directions. Ordered `unread` delivery events
remain audit history; a settled identity requires exactly one matching final outcome, except
`not_delivered`, which permits only prior `unread` events. The archived
`current_candidate_verifications` view must match an exact pinned R7-source or current-main
production definition. Post-run input contains one private row per task with independent
correctness and qualification fields; the public report emits only counts and their cross-matrix.
Every runtime-current identity has exactly one private stricter-evaluator decision, and every
exclusion uses a registered synthetic rule; the reporter never invents an R7 reason. Evidence items
and distinct stored objects remain separate counts. Lane durations use the run's single
`started_at`/`finished_at` interval, clip out-of-window portions, and report additive lane time,
union wall-active time, and concurrent excess separately. Missing native usage is JSON `null`, not
zero. When supplied, usage has exactly one row per attempt; a metric's complete total stays null if
any attempt value is missing.

`scripts/reconcile_run_report.py` reads private row-level evaluation metadata from a caller-owned
JSON file and writes only the sanitized report to stdout. Task and attempt identities, source path,
and run ID are never emitted. Public policy/rule identifiers come from fixed registries, not
caller-provided labels. The module does not contain R7 candidates, candidate digests, authorities,
credentials, or private paths, and it does not execute archived challenge code.

## Touched seams

- `rapido/reporting.py`: standalone archive reader and schema/policy definitions only;
- `scripts/reconcile_run_report.py`: JSON-input/stdout CLI only;
- `tests/test_reporting.py` and its synthetic golden receipt;
- one README link. Live `StateStore`, scheduler, Board, solver, routing, and proof gates are
  unchanged.

## Verification recorded 2026-09-19

Environment: Python 3.11.15, Ruff 0.16.8, pytest 9.1.1.

```text
ruff check rapido tests scripts                                      passed
ruff format --check rapido tests scripts                            passed (90 files)
PYTHONPATH=. pytest -q                                               1074 passed, 4 skipped
PYTHONPATH=. python scripts/sustainability_acceptance.py --cycles 96 passed
```

The sustainability check is synthetic StateStore/queue evidence only, as its receipt states. No
native model, container, Board, network, credential, private archive, or challenge code was used.
