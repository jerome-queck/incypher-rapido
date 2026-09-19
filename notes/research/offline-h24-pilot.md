# Offline H24 pilot protocol

Status: implemented and covered by model-free tests. No native H24 outcome has been run or
unsealed.

`scripts/offline_oracle_pilot.py --experiment h24` is the offline-only runner for the frozen
24-task catalogue in `rapido.offline_h24`. It compares `one_shot` with `evidence_repair`; both arms
require exact `gpt-daybreak-blue-latest` / `xhigh`. A missing or mismatched native descriptor fails
closed, starts no solve, uses no fallback and still emits all 48 terminal rows.

## Frozen execution contract

- The controller derives and preflights all 24 private fixtures before it creates a client or a
  temporary workspace. The private key must be a mode-0600 regular file outside the repository,
  Codex authentication home and work root.
- Each arm receives a separately copied workspace with the same public artifact bytes but distinct
  paths and inodes. Prompts contain only frozen public task metadata, relative artifact paths and
  empty prior-attempt/same-run-memory arrays. Expected values and the oracle file never enter a
  workspace, prompt, RPC, native descriptor projection or receipt.
- H24 uses a dedicated local-artifact-only developer instruction. It does not inherit production
  Board/target authorization. Board access, submissions, networking and fallback are disabled.
- Native clients sharing the authentication home start and validate sequentially. Each admitted
  task then runs its two arms concurrently. The pair shares one absolute deadline: the earlier of
  the 19,800-second global deadline and admission plus the task's frozen wall cap.
- Each arm makes one native `solve` call. The repair arm may request at most one same-thread
  continuation for an eligible evidence rejection. Its remaining budget is clamped to the shared
  absolute deadline and can only decrease; it never receives a fresh grant.
- Expiry, setup failure, provider failure, cancellation and inconclusive outcomes remain in the
  denominator. Global expiry synthesizes terminal timeout rows for every unadmitted arm.

## Receipt and gates

The exact `rapido-offline-h24-pilot-v1` receipt contains 24 outcomes per arm plus the PR4 native
receipt summary. Correctness (`verified_correct` or proof-rejected correct candidate) and
qualification (`verified_correct`) remain independent.

The six easy sentinels are frozen as: `easy-01` plain text, `easy-02` structured JSON, `easy-03`
base64, `easy-04` hex, `easy-05` zip and `easy-06` binary strings. Both arms must qualify all six.
The repair arm's paired qualified-time ratio must have median at most 1.20 and maximum at most
1.50. The receipt records the result; it cannot promote live production autonomy.

An explicitly supplied full source SHA is validated and used as the packaged-image identity without
requiring `.git`. Without a supplied SHA, the runner still inspects Git HEAD and the complete
worktree status; verifier gate cleanliness is not weakened.

## Touched seams and limits

- `scripts/offline_oracle_pilot.py`: H24 preparation, local prompt/staging, fair paired deadlines,
  exact descriptor gate and sanitized 48-row receipt.
- `tests/test_offline_h24_pilot.py`: model-free privacy, preflight ordering, descriptor, deadline,
  retention, source-identity and sentinel tests.

No live solver routing, target tools, concurrency, Board state, proof gate or production controller
behavior changes. No official practice rerun, archived challenge script, native H24 result or
private candidate is part of this change.

## Verification

Recorded on 2026-09-19 in the repository Python 3.11 environment:

- Focused Ruff lint and format checks passed for the owned runner and test.
- Warning-strict focused pytest passed 123 tests across the H24 fixture, H24 pilot, compatible
  offline pilot and native-receipt suites.
- Full repository pytest passed 1,202 tests with four platform skips on the final bytes.
- The 96-cycle synthetic sustainability check passed.
- Independent `gpt-daybreak-blue-latest` / `xhigh` review reported no remaining P0-P3 findings.
- No native model, H24, Board, socket, target or archived challenge run occurred.

Effective implementation/review peers: `gpt-daybreak-blue-latest` / `xhigh`; no fallback.
