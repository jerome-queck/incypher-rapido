# H24 preregistration and execution boundary

Status: protocol frozen; no H24 outcome or 19,800-second real-clock soak has run or been
unsealed. This note records prospective rules, not a result.

## Frozen experiment

`offline-h24-preregistration-v1.json` is the exact public contract. Its canonical SHA-256 is
`5bb63172e5cab48569b3ca6bdc04e4979656c2ab4aabfbf3d13b43ab2aef922e` on these bytes. The public
order seed is `8a2ffd40fdeef877816275730e7bfce26eed11309b68136d2dcbbf4a4de4ede2`.
Task order is ascending `HMAC-SHA256(bytes.fromhex(seed), ASCII task ID)`, then ASCII task ID.
The explicit 24-ID result is committed in the preregistration.

Both arms are exactly `gpt-daybreak-blue-latest` / `xhigh`. The frozen returned descriptor has
that exact model and effort, `revision_status=unavailable`, and `revision=null`. Runtime comparison
is exact and fails closed. No model or effort fallback is permitted.

One task pair runs at a time through two clients. Shared-home startup is serialized; paired turns
may overlap. Each arm receives one solve. `evidence_repair` may use at most one same-thread,
candidate-free continuation after only `candidate_unobserved` or
`verifier_requires_fixed_observation`. Both arms share the earlier of the task cap and one global
19,800-second deadline. Repair gets no new budget. A host barrier starts the offline runner and
benign soak together; the receipt binds its wall-clock start and deadline, exactly 19,800,000 ms
apart. Cleanup is outside scoring, receives at most 190 seconds, and earns no score.

The 24 task records retain their fixture wall, CPU, memory, and artifact declarations. Per-task CPU
and memory values are fixture-generation/reference-checker design bounds only: the container does
not expose truthful task-arm attribution, so they are not scored as observed runtime gates. The
final row records truthful artifact bytes and enforces that observable ceiling. Container-level CPU
percentage, RSS, PID and OOM observations are aggregate; unavailable samples stay null. The frozen
observable aggregate gates are 1,200% CPU, 24 GiB RSS, 256 PIDs, and a maximum 10-second sample
interval. Resource evidence is never synthesized.

Target network is false. Provider transport is required only for the native model connection. No
Board, challenge, target authority, submission, credential, vulnerable service, archived script,
official-practice task, prior candidate, solution, raw digest, or peer answer is model-visible.

## Immutable post-merge registration

The protocol cannot contain its own final squash SHA or final image digest. After this PR is
squash-merged, but before outcomes begin, create one immutable external registration with exactly:

- schema and the canonical preregistration SHA-256;
- UTC registration time and state `frozen_after_pr6_merge_before_outcomes`;
- clean source commit, source tree, and identical PR6 squash-merge commit;
- immutable `sha256:` image ID, Linux platform, and the same build-source commit.

`validate_source_image_registration` rejects missing/extra fields, dirty source, malformed IDs,
an image built from another source, or a registration not bound to this preregistration. The final
receipt also rejects registration after the run start. This external registration is required;
the runner must not manufacture it after seeing outcomes.

## Final sanitized envelope

The supervisor joins the native H24 receipt, real benign-soak receipt, external registration,
barrier, cleanup and sampled container resources. `evaluate_h24_receipt` is pure and read-only. It
requires exactly 48 task-arm rows in frozen task order then `one_shot`, `evidence_repair`; all 10
state-contract scenarios; and exact closed fields. Failed, unstarted, timed-out, provider-failed,
cancelled and inconclusive rows remain in the denominator.

The adapter validates each native attempt one-to-one against task and arm, reconciles native
outcome/tool counts/configured budget with the public row, and rejects repairs that are not an
eligible same-thread candidate-free continuation. Runtime descriptors admit only bounded public
labels. Runtime startup/preflight and task-pair spans must remain ordered inside their task and
global deadlines. The run timestamp exactly equals the millisecond-aligned barrier; immutable
source/image registration strictly precedes it.

Rows expose only public identity, closed outcome labels, correctness/qualification booleans,
nullable event times and usage, closed spans/counts, repair state, and artifact bytes. Candidate
values, candidate/answer digests, credentials, oracle keys, host paths, authorities, raw model
text, and raw tool payloads have no schema slot. Usage missingness remains null. Span lane time is
additive; active wall time is interval union; overlap is reported separately.

The evaluator independently recomputes `C` and `Q` for both arms at 30, 60, 120, 180, and 330
minutes, plus subgroup totals, `C-Q`, wrong-but-accepted counts, easy ratios, provider-pair
failures, usage missingness, overlap timing, resources, cleanup, privacy and the hard-subgroup
diagnostic. `Q <= C` is enforced per row and checkpoint.

Decision precedence is fixed:

1. invalid model/preflight or more than two provider-affected pairs: `inconclusive`;
2. safety/integrity failure, false accept, easy regression, or lower B raw correctness:
   `no_justified_change`;
3. B gains at least two non-easy raw-correct tasks with no easy loss: `capability_signal`;
4. equal raw correctness, B gains at least three qualified-correct tasks, and at least three
   repair opportunities: `conversion_only_signal`;
5. fewer than three repair opportunities: `inconclusive`;
6. otherwise: `no_justified_change`.

A B hard raw score below three of six is reported only as an offline diagnostic. No decision
automatically promotes production live autonomy.

## Safe execution boundary

Execution is authorized only after the preregistration PR is green and squash-merged, the exact
clean source and immutable image are externally registered, all 24 private fixtures pass preflight
before clients start, and a fresh private oracle exists outside source, authentication and model
workspaces. Start both pre-created runners at the same future barrier. Run the offline H24 pairs
and the no-socket real-clock controller soak in parallel for the original deadline. Do not add
filler model calls after native work drains. Preserve any failed or invalid run; at most one
complete rerun follows a separately documented infrastructure fix and a new private seed.

After creating the external registration and private directories, the only execution entry point
is the supervisor. Use its descriptor-only gate first, inspect and retain that receipt, then use the
same immutable inputs for execution:

```sh
PYTHONPATH=. .venv/bin/python scripts/offline_h24_supervisor.py descriptor-preflight \
  --repository "$RAPIDO_REPOSITORY" \
  --preregistration "$H24_PREREGISTRATION" \
  --registration "$H24_REGISTRATION" \
  --auth "$H24_AUTH_DIRECTORY" \
  --work "$H24_PRIVATE_WORK_DIRECTORY" \
  --output "$H24_PRIVATE_OUTPUT_DIRECTORY"

PYTHONPATH=. .venv/bin/python scripts/offline_h24_supervisor.py execute \
  --repository "$RAPIDO_REPOSITORY" \
  --preregistration "$H24_PREREGISTRATION" \
  --registration "$H24_REGISTRATION" \
  --auth "$H24_AUTH_DIRECTORY" \
  --work "$H24_PRIVATE_WORK_DIRECTORY" \
  --seed "$H24_PRIVATE_ORACLE_KEY" \
  --output "$H24_PRIVATE_OUTPUT_DIRECTORY"
```

The supervisor creates both hardened containers before one 30-second-future barrier, passes the
same barrier to both runners, samples resources, enforces the original deadline, assembles the
exact public envelope with `build_evaluation_receipt`, and recomputes the decision with
`evaluate_h24_receipt`. Do not invoke the child scripts directly for the scored run.

After the window, stop scoring, allow only the no-credit cleanup grace, prove zero orphaned
processes/fake instances/pending writes/workspace residue, scan the exact public envelope for
private material, and evaluate it with the pure validator. Package only the sanitized receipt and
next decision. Private oracle material and generated workspaces are deleted only after sanitized
evidence is durable.

## Touched seams and verification

- `rapido/offline_h24_evaluation.py`: frozen contract builder, registration validator, exact final
  receipt validator, recomputation, gates and classifier;
- `notes/research/offline-h24-preregistration-v1.json`: exact prospective contract;
- `tests/test_offline_h24_evaluation.py`: synthetic adversarial contract tests;
- `notes/research/offline-h24-execution.md`: prospective execution and evidence boundary.

No production solver, routing, target tool, Board client, proof gate, scheduler, fixture generator,
native runner, container, credential or live state is changed here. On 2026-09-19, Ruff passed for
the evaluator and its tests; the evaluator/pilot/supervisor set passed 98 tests; the repository
suite passed 1,290 tests with four skips. No native, Board, container, H24 outcome, or real-clock
soak run occurred. No result is claimed in this document.
