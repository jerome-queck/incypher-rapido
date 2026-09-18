# Response to the independent 30-minute audit — 2026-09-18

The external package `incypher-rapido-30m-audit-20260918.zip` passed its 31-file checksum
manifest. Its reproduction utility, run against the original private archive with SHA-256
`0f71220e9f46e40232cb70c2e4c5f5b0556c45e784a0364774bc81171c083feb`, reproduced
all discrete counts in the package's `summary.json`. Cross-interpreter floating-point rendering
can differ in the final decimal places. The private archive and candidates remain outside Git.

## Established result

Run `46e0533bca63498d8d3e6d38f45224cd` used source `9bbc767de1693037ebb0c19244e039bc7ab2f764`
for 1,800 seconds. Ten of 15 challenges started initial analysis; 49 attempts made 2,117 tool
calls, with 302 failures. Eleven checkpoint proposals yielded ten final evidence proofs and six
distinct identities. All six submissions returned `already_solved`; none was independently
verified in the run. Current-run validated score was **0/15**. The previous cumulative total
remains three; this run added zero.

The run's terminal state, committed observations, settled effects, and in-run instance cleanup
were reproduced from the archive. Later remote absence and host cleanup were attested in the
issue #19 ledger, not independently recreated by the external audit. Low sampled CPU, memory,
and PID use rules out recorded local resource exhaustion; it does not isolate the source of
elapsed time. The repaired first-pass queue ordering has CI and fake-runtime evidence, but no
post-repair native measurement yet.

A private, post-run exact comparison against the separate task's completed UI-verified writeups
finds **five exact matches among six static challenges**, no mismatches, and one with no candidate.
For the one dynamic candidate, the retained solver implements the same full repeated-digit,
five-trial minimax method as the independently reproduced live writeup; the source-bound trace
shows one connection and a candidate after the fifth trial. The supervisor handles that target's
authenticated proof of work. Under the owner's method-equivalence rule, this is **one dynamic
method match**, yielding a **6/15 post-run practice-method score**. The sanitized trace does not
bind every guess to the retained script, so the method attribution has that limit. This score is
separate from the run-local Board-validated 0/15 and adds no cumulative Board solve. The
candidate-free comparison record is owner-only in Downloads.

## Repairs in this slice

- Whole-attempt candidate attestation reports one closed rejection reason. A complete history
  containing an earlier supplied-input conflict reports `candidate_supplied` while still
  rejecting the final proof. The old proof API and anti-taint policy remain intact.
- Text monitoring separately labels initial analysis starts and lifecycle-settled challenges.
  A terminalized, never-started challenge cannot be mistaken for exposure.
- The issue #19 ledger distinguishes retained checkpoints from final proofs, four Recovery
  projections from five empty Verifier projections, carry retention events from unique files,
  and low local utilization from an unmeasured causal bottleneck. Its lifecycle status now
  reflects the owner's post-observation closure amendment.
- `scripts/summarize_audit_memory.py` generates the role/episode and carry counts from the
  audit's sanitized CSVs. The checked output is
  `notes/research/30m-audit-memory-summary-2026-09-18.json`; it includes input hashes and
  leaves the unique-file count unknown because retention events may repeat a file.

The 241 argument-stage failures identify interface friction, but do not prove a schema-handler
defect. The six practice submissions do not establish answer correctness. Neither fact warrants
weakening argument validation, provenance, the sandbox, or the score definition.

## Next measurement

Keep an answer and method oracle outside the solver image, state, workspace, prompt, tool output,
and same-run memory. A separate owner task is verifying the practice challenge flags and live
methods. Its draft is provisional. Once complete, use it **after** a fresh run to score static
candidate equality. For dynamic challenges, compare the solver's private, source-bound trace
with the independently reproduced method: the required data-dependent steps, target effect,
and path from observed output to candidate must be present. Repeat the method on a fresh
instance where needed, without comparing instance-specific flag strings. Mark incomplete traces
unverifiable. Under the owner's scoring rule, a matched, independently verified dynamic method
counts its run candidate as correct in the post-run practice benchmark. Report that category
separately from exact static matches and Board `correct` verdicts; a generic `already_solved`
verdict never validates a candidate by itself.
This yields a labeled practice-regression result, not a held-out generalization result.

In parallel, establish a benign hidden-answer offline pilot: exact model/effort selection,
identical role and tool contract per arm, no fallback, an oracle isolated from model workspaces,
and correct/wrong/unverifiable outcomes. Test the evaluator with deliberately wrong answers
before relying on model results. Compare Daybreak/xhigh and Luna/xhigh only under matched
conditions; the 30-minute role mix does not support a causal ranking. Evaluate the fresh
Verifier separately with correct, wrong, and unprovable candidates. Record elapsed phases and
actual native usage when available; missing usage stays missing.

A further 1,800-second practice run cannot guarantee 15 full first passes with five slots,
800-second work, and the 600-second admission floor. The practice oracle is now complete, so
the relocated 19,800-second acceptance run can use post-run correctness scoring. That full-duration
gate remains unpassed.

## Registered follow-up diagnostic

After reviewed fixes merge, run one unattended 1,800-second practice diagnostic in the final
container. Create empty state/workspace, fetch every challenge afresh, and keep the verified
writeups and score file outside the image, prompt, workspace, native home, and carry memory.
Use five challenge slots, 20 model lanes, an 800-second first-pass baseline, and the exact
four-peer roster for each initial challenge: two Daybreak/xhigh Leads, one Luna/max Specialist,
and one Luna/xhigh Specialist. Model or effort mismatch fails the run; no fallback. Keep Board
watch, qualified autonomous submissions, and receipt-bound dynamic cleanup enabled. Record the
source SHA, immutable image ID, effective nonsecret config, and exact container/state identity
before launch.

Targets are at least 10/15 fresh initial starts, at least 6/15 post-run practice-method matches,
zero current-run Board-validated solves as the diagnostic baseline, and a cumulative Board total
of three. Report actual values even if targets fail. Count static exact matches and independently
reproduced dynamic-method matches only after the run; Board `already_solved` has no correctness
weight. A source-run `correct` or same-run deterministic verification can raise the current-run
and cumulative counts under the existing rules. The terminal gate requires zero pending/unread
submissions, zero owned instances, zero leaked process/workspace state, and durable cleanup of the
exact run after its private evidence is archived.
