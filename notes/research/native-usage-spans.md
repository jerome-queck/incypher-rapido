# Native usage and span receipt contract

Status: implemented for the benign offline pilot. No native H24 outcome was run or unsealed.

`rapido.native_receipts` is a pure accounting module. Its small interface builds one
`rapido-native-attempt-receipt-v1` row and summarizes an exact expected set as
`rapido-native-receipt-summary-v1`. The existing model and Verifier pilot receipts are separately
versioned as v2 when they embed this new contract.

## Accounting rules

- Every expected `(task_id, arm_id)` has exactly one terminal row. Duplicate, missing, unexpected,
  malformed, failure, cancellation and inconclusive rows fail or remain visible; they are never
  dropped from a denominator. An externally cancelled turn attaches its complete sanitized row to
  the re-raised `CancelledError`; its projection retains bounded cumulative usage and safe
  successful-call duration, but no raw call arguments or native event. A repair timeout/provider
  failure without a terminal native result retains the completed first-turn usage, calls, span and
  budget as its cumulative prefix.
- Native input, output, cached-input and reasoning usage fields are always present and nullable,
  using PR1's `policy.native_attempt_usage.v1`. Provider totals are not invented. The controller
  projects the exact-turn `thread/tokenUsage/updated.tokenUsage.total` notification to these four
  bounded fields; `totalTokens` is ignored. A continuation's final snapshot is explicitly
  cumulative and counted once. Its repair delta is `final - first` only when both values exist and
  are monotone; every field says `monotone`, `nonmonotone`, `incomplete`, or `not_applicable`.
- Every span uses an offset from one benchmark-global monotonic `t0`. Lane milliseconds are
  additive. Wall-active milliseconds are the interval union. Their difference is overlapping lane
  exposure. Tool-call timing is nested diagnostic exposure and is never added to turn wall time.
- Budgets retain configured, actually granted, after-first and terminal remaining milliseconds.
  Remaining values cannot exceed the grant or increase between turns.
- Argument repair is a one-to-one FIFO closure: one later successful call closes at most one prior
  argument-stage failure of the same canonical tool. Success plus argument/execution/result/untyped
  call counts must equal the cumulative count, and first plus repair calls must also equal it. A
  closure cannot exceed eligible failures or successful repair calls. Observed plus missing
  successful-call timings must equal the successful-call count.

## Privacy and feedback boundary

The public shape has exact top-level and nested field sets plus closed outcome, stage, status,
failure and constraint domains. Only registered task/arm identities, enums, counts and durations
survive. Raw tool arguments, model prose, paths, authorities, candidates, candidate fingerprints,
digests, credentials and oracle material are not copied.

PR70's existing `HostObservation` structural failure stage is reused to classify argument failures;
its diagnostics are not reimplemented. The Codex seam captures exact-turn cumulative native usage
and measures successful tool-call duration with the controller's monotonic clock. Both remain on
controller-side `TurnResult` receipt fields. They are absent from the RPC response,
`HostObservation`, durable evidence, same-run memory and model input. Receipt values never change
routing, repair eligibility, prompts, proof acceptance, or tool authority.

## Touched seams and limits

- `rapido/native_receipts.py`: pure validation, accounting and interval union.
- `rapido/codex_app.py`: exact-turn cumulative usage snapshot and successful-call controller delta.
- `scripts/offline_oracle_pilot.py`: v2 receipt adapter over existing native events and PR70 calls.

Specialist `unverifiable` and Verifier `no_candidate`, `solver_output`, and rejected outcomes map to
receipt `inconclusive`; verified right/wrong executions remain `completed`. This classification is
accounting-only and does not alter evaluator correctness.

The current pilot has no distinct queue or evidence worker stage, so it emits only fixture, first
turn and optional repair intervals per attempt. Startup, model validation and cleanup now also
carry offsets from the same benchmark-global `t0`, while remaining separate runtime spans. PR5 may
wire the same accounting interface to the frozen H24 manifest and global deadline. This PR does not
change live scheduling, model/effort selection, tools, retries, Board behavior, proof policy or
production concurrency.

## Verification

Recorded on 2026-09-19 in the repository Python 3.11 environment:

- Focused Ruff lint/format passed for the six touched Python files.
- Focused pytest passed: 178 tests across native receipts, offline pilot, Codex app and PR1
  reporting, with Python warnings treated as errors.
- Full repository pytest passed: 1,185 tests, with 4 Linux-only skips.
- The 96-cycle synthetic sustainability check passed.
- No native model, Board, socket, target or H24 outcome run.

Effective implementation/review roster: `gpt-daybreak-blue-latest` / `xhigh`; no fallback.
