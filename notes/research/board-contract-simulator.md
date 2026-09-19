# Benign Board-contract simulator

Status: implementation contract. Native H24 outcomes and the 19,800-second real-clock soak remain
unrun until the final preregistration PR.

## Boundary

`rapido.board_contract` drives the real `BoardClient` method shapes through an in-process scripted
`Transport`, writes lifecycle facts through the real `StateStore`, and reads queued state through
`DurableJobControl.inspect`. It opens no socket. The fake instance registry contains only opaque
generation labels. It does not implement CTFd, discovery, scoring, credentials, targets, vulnerable
services, exploits, model routing, proof policy, or network/platform fidelity. These ten results are
controller-reliability evidence and stay outside the 24-task H24 correctness denominator.

The receipt exposes one exact top-level schema, an exact fact allowlist per scenario, and a typed
domain or closed enum for every fact. Validation rejects extra credential, API-key, private-value,
candidate, digest, path, authority, and oracle fields; arbitrary secret-like values in otherwise
allowed string slots; flag-shaped values; URLs; host-port authorities; long hex; and POSIX,
Windows-drive, or UNC paths. Private seed-derived values and generation receipts remain internal.
Simulator state and work directories are disposable.

## Frozen scenarios

1. `distinct_submission_outcomes`: correct, incorrect, and historical already-solved remain distinct.
2. `ambiguous_write_reconciled_once`: response loss after one simulated write is explicitly
   reconciled without a second write.
3. `transient_read_and_permanent_auth`: read-side HTTP 502 recovers; exact HTTP-401 `BoardError`
   runtime classification remains separate from durable model attempts. No production auth-failure
   event exists, so this scenario does not claim one.
4. `queued_job_unstarted`: one isolated admitted challenge derives zero attempts, submissions, solves,
   and current verifications from `StateStore`/`ControlView`.
5. `fresh_generation_exact_answer`: real producer and fresh verifier attest the unchanged private
   exact value; `current_candidate_verifications` records the fresh instance generation.
6. `different_answer_separate_axes`: a third generation and different producer value have no current
   exact verification. The synthetic method/oracle label is a separate, explicitly named axis.
7. `changed_bytes_reset_context`: two different artifact-byte generations at the same Board file
   reference run through `_probe_material_contexts` and `_admit_catalogue_revisions`; the actual
   `_typed_same_run_memory` and `build_turn_prompt` path excludes old observations and private data.
8. `watch_change_original_deadline`: the watcher starts at t0, observes a scripted mid-window HTTP
   502 and distinct late catalogue change, then drains under the unchanged original deadline.
9. `deadline_cancel_cleanup`: actual `DurableJobControl.drive` creates a benign dynamic-instance
   lease, cancels a blocking model-free target phase at deadline, deletes that lease, and leaves no
   active/queued work, pending writes, owned instances, or workspace data. One create and one delete
   make the zero-owned result non-vacuous.
10. `serialized_startup_independent_turns`: the existing offline verifier-repair pilot runs with
    model-free clients, proving PR71 serialized startup and concurrent paired turns across 24 result
    rows; the existing PR70 diagnostic projection redacts private-like content.

## Clock and soak

`SystemClock` delegates to the exact prior `time.monotonic`/`asyncio.sleep` primitives.
`ManualClock` accelerates retry, polling, and idle-watch transitions. `Orchestrator` accepts the clock
only at construction; production defaults are unchanged. `DurableJobControl.drive` forwards this
optional seam for tests.

The 19,800-second preregistered schedule freezes the transient at 9,900 seconds and the late change
at 18,900 seconds. Short smoke runs use explicitly compressed quarter/three-quarter offsets so the
production read guard can observe both events without weakening the full-duration schedule.

Run the accelerated suite, then the short separately labelled real-clock smoke:

```sh
PYTHONPATH=. pytest -q tests/test_board_contract.py
PYTHONPATH=. python scripts/board_contract_soak.py --accelerated --duration-seconds 19800
PYTHONPATH=. python scripts/board_contract_soak.py --duration-seconds 2
```

PR6 will run the preregistered real-clock command with `--duration-seconds 19800` in parallel with
H24. It must retain failures/inconclusive results and use the declared cleanup grace; this PR does
not claim that soak has run.

## Touched seams and verification

- New: `rapido/clock.py`, `rapido/board_contract.py`, `scripts/board_contract_soak.py`.
- Minimal production seam: injected clock in Board retry, instance lifecycle polling, and idle watch;
  default behavior remains `SystemClock`.
- Reused, not reimplemented: Board parsing, durable state/control inspection, generation-scoped
  candidate proof, prompt memory, deadline cancellation, instance receipt, PR70 diagnostic
  projection, and the PR71 offline-pilot startup/turn contract.
- No source-database mutation outside a fresh disposable simulator database.

Focused verification on macOS, Python 3.11.15, Ruff 0.16.8, pytest 9.1.1:

- Ruff check/format: pass for touched Python files.
- Contract suite with `RuntimeWarning` promoted to error: 21 passed. This includes all accelerated
  transitions and one separately labelled 2-second real-clock smoke; no unhandled task warning.
- `tests/test_board_contract.py`, `tests/test_board.py`, `tests/test_state.py`,
  `tests/test_orchestrator.py`, `tests/test_control.py`, and `tests/test_offline_oracle_pilot.py`:
  289 passed.
- Standalone accelerated 19,800-second simulation and separately labelled 2-second real-clock smoke:
  10/10 passed each. The deferred item is the 19,800-second **real-clock** PR6 soak.
- `git diff --check`: pass.
- Full repository pytest: 1,163 passed, 4 Linux-only skips.
- 96-cycle synthetic sustainability: passed.
