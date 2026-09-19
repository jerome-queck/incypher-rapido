# H24 offline evaluation evidence — 2026-09-20

Status: sanitized final evidence for one terminal H24 attempt. The native H24 child and the
19,800-second benign Board-contract soak both exited zero, but the outer supervisor correctly
failed the run's private-cleanup gate. The pure evaluator returned `no_justified_change`. This is
not a passing acceptance run and does not authorize production live-autonomy promotion.

## Boundaries

This evidence is benign and offline. It used no Board, target authority, official practice rerun,
archived challenge script, previous candidate, previous solution or live submission. The model saw
only the frozen H24 fixtures and local-artifact tools. Candidate values, candidate/answer digests,
credentials, oracle keys, host paths, authorities, raw model text and raw tool payloads remain
outside the repository.

R7 remains a separate accepted result: 15/15 post-run correctness (six static exact and nine
dynamic method matches), with all 15 finalized proof-backed producer candidates present by
2h51m50s. Its 5.5-hour run tested endurance and continued verification; it was not time-to-first
15. Keep its five axes separate: post-run correctness 15, new Board-correct outcomes 0,
already-solved submission identities 42, runtime current verification 2, and the stricter report's
reported metric 0. The stricter report's zero current scoped rows conflicts with the archived SQL
view and still needs a versioned reporting explanation, not a new live solve or weaker proof gate.
No R1–R6 score or causal comparison is claimed because the two named companion sources were not
available to the audit.

## Retained attempts

| Attempt | Terminal class | Scored evidence | Disposition |
| --- | --- | --- | --- |
| v3 | setup failure: packaged wrapper omitted `/opt/rapido-eval` | none | immutable external failure retained; no candidate inspection |
| v4 | inconclusive: `soak_packaged_pilot_unavailable` | none; H24 interrupted only after harness failure | immutable sanitized failure retained externally; private partial state not reused |
| v5 | failed: `private_cleanup` | complete 48-row receipt, 10/10 soak, pure evaluation | repository artifacts below; no automatic rerun |

The v5 source was `963edb5e3d2558991adb4ed7411f85365f8fd819`. Both scored children
exited zero. The supervisor ran 19,841.38 seconds, removed the exact child containers, observed no
orphans, preserved authentication and parsed both public final artifacts. Its unprivileged UID
10001 process could not unlink the top-level empty work directory or oracle file because their
common private-volume parent was root-owned mode `0755`. PR 80 now rejects that condition before
Docker or model work; it does not alter this historical receipt.

## Public artifacts

- `offline-h24-attempt-v5-evaluation-receipt-2026-09-19.json`: exact closed-schema final receipt,
  including all 24 outcomes per arm and all 10 state-contract scenario results.
- `offline-h24-attempt-v5-evaluation-result-2026-09-19.json`: independent recomputation of counts,
  gates, checkpoints, timing, usage and decision.

The receipt passed its exact closed-schema validator and the committed evaluation result is the
byte-for-byte output of the pure recomputation. The final receipt's privacy scan passed. The
sanitized terminal supervisor receipt remains externally retained; only its lifecycle/resource
projection needed to interpret the decision is recorded in this note.

## Outcomes

| Arm | Raw correct C | Qualified correct Q | C−Q | Easy C/Q | Non-easy C/Q | Hard C | False accepts |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `one_shot` | 24/24 | 11/24 | 13 | 6/6 | 18/5 | 6/6 | 0 |
| `evidence_repair` | 24/24 | 12/24 | 12 | 6/6 | 18/6 | 6/6 | 0 |

Subgroup qualified counts were identical except medium: one-shot qualified 2/6 and repair
qualified 3/6. The only qualification delta was `h24-medium-03`, where one-shot was
`candidate_unobserved` and one same-thread repair qualified the already-correct outcome.

Both arms reached raw correctness 24/24 by 999,654 milliseconds after the shared barrier
(16m39.654s). Model work then stopped. The remainder of the 5.5-hour window was the preregistered,
model-free endurance and state-contract soak; it was not needed to first solve the 24 tasks.

The same C/Q counts hold at the 30, 60, 120, 180 and 330 minute checkpoints because every H24 row
was terminal before the first checkpoint. Failed, inconclusive and unqualified rows remained in
the denominator.

## Capability versus conversion

- Capability: no signal. Both arms were raw-correct on all 24 tasks and on all 18 non-easy tasks;
  repair gained zero raw-correct tasks, below the frozen +2 non-easy threshold.
- Conversion: one observed qualification conversion, from Q=11 to Q=12. There were 13 repair
  opportunities, but the frozen equal-C rule requires a +3 qualified gain; the observed +1 is not
  a `conversion_only_signal`.
- Easy protection: both arms stayed raw/qualified 6/6. Median paired repair/one-shot qualified
  latency was 1.076, under the 1.2 ceiling, but the maximum was 1.563 on `h24-easy-04`, above the
  frozen 1.5 ceiling. The easy non-regression gate therefore failed.

The preregistered classifier returned `no_justified_change`. Cleanup/privacy aggregation and the
safety/integrity aggregate also failed because private deletion did not complete, although the
closed public receipt privacy scan itself passed.

## State-contract and runtime evidence

All 10 benign simulator scenarios passed: distinct submission outcomes; ambiguous-write
reconciliation; transient read versus permanent auth; queued-unstarted accounting; fresh exact
answer; separate answer/method axes; changed-byte context reset; original-deadline watch change;
deadline cancellation/cleanup; and serialized startup with independent turns. They contribute no
H24 correctness rows.

| Observation | H24 child | Soak child |
| --- | ---: | ---: |
| Exit code | 0 | 0 |
| Peak CPU | 12.79% | 11.79% |
| Peak RSS | 265,289,728 bytes | 39,111,884 bytes |
| Peak PIDs | 108 | 3 |
| Samples | 201 | 3,960 |
| Maximum observed sample gap | 6.003s | 6.003s |
| OOM killed | false | false |

The evaluator reported additive lane time 1,551,023ms, union active wall time 999,582ms and
overlapping lane time 551,441ms. These quantities intentionally differ; overlap is not double
counted as wall time.

| Arm | Input | Cached input | Output | Reasoning | Missing usage attempts |
| --- | ---: | ---: | ---: | ---: | ---: |
| `one_shot` | 1,241,578 | 930,242 | 17,451 | 10,084 | 0 |
| `evidence_repair` | 1,994,866 | 1,640,136 | 35,264 | 20,666 | 0 |

Usage is the final cumulative snapshot counted once per attempt. The schema preserves null rather
than manufacturing zero when a provider field is absent; this run happened to observe every field.

## Decision

Do not change live model/effort routing, target tools, target selection, retries, instance
concurrency, proof policy or production autonomy. The repair arm showed neither the frozen
capability gain nor the frozen conversion gain, and the easy-latency and private-cleanup gates did
not pass. There is no automatic production promotion.

Do not automatically rerun. If the owner later requires one protocol-clean confirmation, it must
be separately authorized after PR 80, use a new private seed and fresh empty state/workspace, keep
the same frozen H24 contract, and retain this failed attempt. The current next decision is to keep
the production configuration unchanged and preserve the result as `no_justified_change` with a
failed outer cleanup gate.

## Verification record

- PR 80: Ruff check and format passed; 136 focused evaluator/supervisor tests passed; full pytest
  passed 1,395 with 4 Linux-boundary skips; the synthetic sustainability check passed 96/96; all
  four CI jobs passed; independent Daybreak/xhigh review reported no remaining findings.
- This evidence package: 137 focused evaluator/supervisor/evidence tests passed; full pytest passed
  1,396 with the same 4 Linux-boundary skips; Ruff and format passed; synthetic sustainability
  passed 96/96. The first new-test lint/format check reported import ordering and formatting only;
  the repository formatter corrected both before the clean rerun. Independent Daybreak/xhigh
  review findings on package scope and supervisor-schema coverage were fixed; re-review was clean.
- This evidence PR performs no native, Board, target, model or archived-challenge execution. Its
  tests validate the receipt's exact closed schema through the pure evaluator, exact result replay,
  row/scenario cardinality, privacy-field boundaries and the summarized decision counts.
