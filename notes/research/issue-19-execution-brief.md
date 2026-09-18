# Issue 19 execution brief

Status: active. This document is the durable architecture, experiment, decision, and acceptance
ledger for issue [#19](https://github.com/jerome-queck/incypher-rapido/issues/19). It is sanitized:
no candidate, candidate digest, credential, challenge description, target authority, instance
receipt, raw model output, or tool payload belongs here.

## Outcome contract

Own issue #19 through verified completion without steering. Choose architecture from controlled
comparisons; implement adaptive failure routing, cooperating Lead/Specialist/Verifier/Recovery
roles, typed same-run memory, private candidate retention and deterministic verification,
replayable ordering, evidence-earned extensions, full catalogue coverage, measured use of the
8-CPU/24-GiB/256-PID/~500-GiB envelope, and crash-safe 5.5-hour recovery. An unchanged failed
action is never retried.

Completion requires one pre-registered, fresh-state, exact-final-image, unattended mixed-model run
with a 19,800-second work-admission budget, autonomous qualified submissions, and managed instances
enabled. Every challenge must receive at least one exact `gpt-daybreak-blue-latest`/`xhigh` peer;
additional exact OpenAI peers may use the pre-registered Luna xhigh/max plan. It must analyze all 15 catalogue entries,
submit every freshly derived qualified candidate including candidates for Board-solved entries,
receive at least one new HTTP-200 `correct` verdict, bring cumulative autonomous solves from three
to at least four, and prove that a new routing, context, collaboration, recovery, or verification
mechanism materially contributed. Generic `already_solved` is never candidate validation.

The gate also requires each assigned model/effort exactly with no fallback; no manual candidate relay or operator
steering; no pending effect, indeterminate owned instance, process/workspace/state leak, or
security/lifecycle regression. Sanitized evidence must merge before that exact run's container,
state, and workspace are deleted. Authentication is preserved. Acceptance will not be lowered
after results are observed.

## Mandatory baseline facts

- Source baseline: `b10a859` on 2026-09-16. Untouched local verification: Ruff check and format
  clean; 586 tests passed and one skipped on Python 3.12.13.
- Issue #11's exact run used `gpt-daybreak-blue-latest`/`xhigh` without fallback, completed all 15
  initial waves and 30 episode-0 lanes, but verified only 1/15 in that run. Its original >=3/15
  gate failed; the later cumulative-three amendment is reported separately.
- Fifteen attempts failed `cyber_policy`; 14 of those were seven dynamic pairs with no tool call.
  Ten standard attempts ended `candidate_provenance` after 186 total calls. Seven retained a
  candidate fingerprint somewhere, but only one did so in a successful source-bound observation;
  none recorded model-supplied candidate provenance.
- No timeout, quota, rate, overload, transport, OS, OOM, restart, SQLite, workspace, or
  pending-effect failure explained the score loss. Capacity was therefore not the causal baseline
  bottleneck, despite very low measured host use in an older whole-catalogue run.
- The later Board inactive shape (HTTP 200, `success=false`, no endpoint/timestamps) exposes no
  endpoint but is not the established HTTP-404 absence proof. Dynamic mutation remains fail-closed
  until current semantics are independently established.
- The current implementation uses a monolithic orchestrator, a FIFO episode queue, identical
  retry topology, lane-local same-lineage carry, two-candidate exact agreement, serialized
  submission reservation, and receipt-bound instance cleanup. Failed provenance candidates are
  not retained in a private verification surface.

Primary repository evidence:

- [`issue-11-completion-evidence-2026-09-16.md`](issue-11-completion-evidence-2026-09-16.md)
- [`dynamic-acceptance-2026-09-15.md`](dynamic-acceptance-2026-09-15.md)
- [`README.md`](../../README.md)
- [`deploy/CONTAINER.md`](../../deploy/CONTAINER.md)

### Read-only predecessor principles

`/Volumes/Working/001 Projects/incypher-ctf` was inspected only as design research. No code,
answer, artifact, run state, or scale assumption is reused. Its relevant records are largely v2
planning contracts, so each principle remains a hypothesis until Rapido's controlled evidence
supports it:

- A deterministic controller owns admission, capabilities, deadlines, verification, and effects;
  model roles receive no implicit authority (`docs/adr/0042-*`, lines 13-197).
- Observations are host facts; model Claims are never promoted to observations. Candidate
  derivations cite exact evidence and transformations, and confidence cannot replace verification
  (`CONTEXT.md`, lines 387-467; `docs/adr/0045-*`, lines 53-89 and 136-177).
- One sequencer makes claims/admissions durable before work or effects. A restarted Boot replays
  the canonical sequence, closes interrupted identity, and opens a fresh bounded successor; it
  never resumes half-observed identity (`docs/adr/0043-*`, lines 15-119 and 144-199).
- Confirmed progress means a replayable environment transition, not narrative novelty. The
  predecessor's 120-second/three-grant extension dial is provisional and is not imported
  (`docs/adr/0035-*`, lines 27-98).
- Recovery contains the smallest safe scope, fingerprints the incident, and permits another
  engagement only after changed evidence, tactic, route, model, or environment (`docs/adr/0046-*`,
  lines 20-199).
- Submission uncertainty is at-most-once and narrowly fences effects; Board presence establishes
  instance existence while durable solver state establishes ownership (`docs/adr/0052-*`, lines
  14-173; `docs/adr/0044-*`, lines 5-101).

The predecessor's own measurements caution against importing complexity: 20/26 closed attempts
reached a step cliff, zero of 1,003 steps created checkpoints, and 10/18 model invocations were
killed. Its proposed 1-2 lane/0-2 specialist envelope had no controlled Board-level concurrency
proof. This supports an incremental B-versus-A comparison, not wholesale adoption.

### Current agent-system research

The primary-source matrix is in
[`issue-19-agent-systems-sources.md`](issue-19-agent-systems-sources.md). Its controlled evidence
changes the architecture burden:

- *Towards a Science of Scaling Agent Systems* v3 compared 260 configurations over six
  benchmarks. Multi-agent effects ranged from +80.8% on decomposable financial reasoning to
  -70.0% on sequential planning; its cross-validated architecture-selection R² was 0.373, or 0.413
  with task-grounded capability. Role count and fan-out must therefore be selected per task shape,
  not assumed beneficial.
- Anthropic's deployed research system supports explicit lead assignments, compressed specialist
  artifacts, and separate citation checking, but reports about 15x chat token use. Its +90.2%
  internal improvement is not an equal-budget causal result for this domain.
- Managed-agent and long-running-harness reports support separating durable events, disposable
  workspaces, generation, and evaluation. They are operational accounts, not proof that four
  permanent model agents improve solve conversion.
- Temporal's replay contracts support deterministic command history, typed non-retryable errors,
  and idempotent/reconciled effects. They also expose the crash window: an effect may happen before
  its completion record, so local replay alone can never justify a repeated POST.
- Typed graph state and private output channels help structure epistemic status but do not prove
  authorization or secrecy. Candidate-vault isolation needs explicit storage, lifetime, access,
  and deletion controls.
- No reviewed primary source supports longer live deadlines here. Evidence-earned extensions must
  redistribute only within the fixed per-attempt and 19,800-second absolute ceilings and must be
  allowed to lose their comparison.

Policy or authorization rejection is non-retryable unless a separately pre-approved, controlled
configuration—not a refusal-evading rephrase—has already proved a lawful materially different
route. Deterministic local analysis or terminal containment remains valid; provider/model fallback
does not.

## Decision method

Architecture is selected lexicographically: preserve authority/security/lifecycle invariants;
then maximize freshly validated solve conversion and full coverage; then minimize elapsed time,
unchanged repeats, tool use, context volume, and resource waste. A result that weakens source
binding, candidate sensitivity, target allowlisting, exact model enforcement, serialized effects,
or restart cleanup is disqualified regardless of score.

### Controlled alternatives

| Alternative | Structure | Expected advantage | Main falsifier |
| --- | --- | --- | --- |
| A: current episode retry | Two peer lanes, FIFO retry, same prompt contract | Smallest change and strongest known lifecycle surface | Reproduces policy/provenance dead ends or repeats tactics unchanged |
| B: durable role controller | One deterministic Lead routes bounded Specialist, Verifier, and Recovery engagements through a typed same-run ledger and private candidate vault; roles are responsibilities, not permanent processes | Separates derivation, verification, and recovery while retaining one authority owner | Added context/coordination costs do not improve fixture conversion or replay |
| C: free-form agent mesh | Agents exchange narrative and choose peers dynamically | Maximum apparent flexibility | Non-replayable decisions, candidate contamination, excess context, or unsafe shared authority |

Alternative C is disqualified as a production candidate because narrative exchange cannot prove
replay, independence, or private-state isolation; it remains a negative comparison only.
Alternative B must still earn selection against A with safe fixtures and native non-submission
calibration. The controller—not a model—owns model selection, budgets, effect authority, queue
order, failure classification, and candidate admission.

### Interface comparison and architecture decision

After the required direct Astra-to-Daybreak switch, three Daybreak/xhigh lanes compared radically
different Interfaces against the same constraints:

1. **Minimal:** `open / advance / inspect`, with injected Agent and Effect ports. Highest explicit
   lifecycle leverage, but broad tagged ports would hide several unrelated external contracts.
2. **Flexible:** `open / drive / public_view` plus a startup-sealed extension catalogue. Best for
   hypothetical new roles, recipes, failure types, and schedulers; worst replay/version burden and
   largest Interface. The current evidence does not justify that variation.
3. **Common caller:** one `drive(config, board, runtime)` operation, concrete SQLite/filesystem,
   and only the existing Board/native seams. Correct execution is trivial, but a drive-only
   Interface lacks first-class sanitized inspection and can become a god-shaped implementation.

**Selected architecture:** a closed-core common-caller/minimal hybrid. The external control Module
has two entry points:

```python
outcome = await DurableJobControl.drive(config, board=board, runtime=runtime)
view = DurableJobControl.inspect(state_path, run_id=None)
```

The Interface exposes immutable run contracts, sanitized outcomes/views, typed terminal errors,
and the existing Board/native adapters. SQLite, filesystem, clocks, reducer, queue, router, vault,
verifier, and resource governor remain private implementation or internal seams. Role/failure/job
kinds are closed typed unions for issue #19, versioned in durable records; there is no plugin
catalogue until two real implementations justify one.

The implementation is split internally into cohesive journal/reducer, routing, vault/verification,
and scheduling/lifecycle Modules while preserving this one deep external control Interface. A
compatibility `Orchestrator.run()` delegate may exist only during migration and must not become a
second authority.

Why selected from comparison:

- E0 and issue #11 prove the missing behavior is durable typed routing and private verification,
  not generic extensibility or more peer conversation.
- The closed design has the smallest caller knowledge while retaining the inspection needed for
  pending-effect and cleanup truth.
- Existing Board/native production and fake adapters are real seams; a generic storage, role, or
  recipe adapter would be hypothetical.
- The flexible catalogue is rejected unless later controlled fixtures require core control-flow
  edits for an evidenced new failure/recipe. The single-call-only design is rejected if tests or
  operators must bypass it to inspect durable safety state.

Immediate disqualifiers remain: any unchanged retry, replay divergence, deadline reset, fallback,
private leak, unsafe candidate admission, duplicate/ambiguous repeated effect, incomplete coverage
reported complete, or cleanup uncertainty hidden as success. Equal-budget E1-E3 may still falsify
the selected implementation and retain architecture A; they cannot relax these constraints.

## Pre-registered experiments

No final live acceptance state or workspace will be created until these experiments, independent
review, merged source, exact image, and protocol are fixed.

| ID | Comparison | Fixed measurements | Pass/decision rule |
| --- | --- | --- | --- |
| E0 | Current code on deterministic representatives for policy, provenance, disagreement, timeout, tool, quota, Board, container/restart | Terminal class/subreason, next route, changed-input proof, queue record, effect ownership | Replay reproduces each dead end without external secrets or effects |
| E1 | One authorized-context/prompt variable at a time, submission disabled | Exact model/effort, completion/refusal, first tool call, elapsed, tool count, provenance result | Select only a policy-compatible variant with no scope expansion or safety weakening |
| E2 | Exact peer agreement vs private-retention plus independent deterministic verification | Qualified candidates, false admissions, provenance subreason, elapsed/tool count | New path admits only source-bound deterministic verification and never model assertion alone |
| E3 | FIFO unchanged episode vs failure-specific Lead routing | Per-class conversion, repeated action fingerprints, coverage, elapsed, tool count | Selected route changes tactic/context/tool/role/budget after every failure and improves or preserves safe conversion |
| M1 | Current lane-local carry vs typed challenge-wide earlier-episode memory | Useful context, duplicate tactics/observations, prompt bytes, source linkage, replay, scope/privacy violations | Select typed memory only if it exposes strictly more useful cross-lane context with zero safety regression; confirm conversion in E4 |
| E4 | Mixed P20 default, then measured lower/higher safe peer profiles | CPU, RSS, PIDs, RPM/quota/latency, queue wait, Board/instance pressure, conversion | Keep five-challenge full-wave admission unless a measured provider, host, or lifecycle boundary dominates |
| E5 | Crash points before/after queue admission, evidence/vault commit, submission intent/response, instance create/delete | Replay order, lost/duplicated work/effects, cleanup, DB integrity, residue | One durable owner; no duplicate POST, lost closed work, stale lane, or leaked instance/workspace |
| E6 | Read-only current Board inactive-instance observations with exact request contract | HTTP status, validated body shape, endpoint/timestamp presence, repeated coherence | Mutation allowed only after documented inactive semantics are positively established |

Every experiment records exact source, fixture identity, model/effort when used, configuration,
elapsed time, and a sanitized result. Native calibration is not a submission probe. Live solver
runs use the exact pre-registered OpenAI peer roster with no fallback.

### Owner amendments before mixed-model live measurement

On 2026-09-16, before any issue-19 native or Board solver result was observed, the owner clarified
that live execution is model-agnostic within the configured OpenAI catalogue. Every challenge gets
at least one Daybreak/xhigh peer; cheaper Luna xhigh/max peers may fan out around it, and routed hard,
disputed, verification, or recovery work may earn more Daybreak peers. These are controller-managed
peer threads, not nested agent trees. The initial production default is five active challenges and
four peers per challenge: Daybreak/xhigh Lead plus Luna max, xhigh, and max Specialists, for a full
20-lane wave. Provider RPM/quota is a measured routing input, never permission to fall back.

The owner also requested light implementation-first engineering rather than TDD or framework
expansion. Required security, lifecycle, memory, routing, recovery, review, and acceptance proofs
remain unchanged.

Before any 19,800-second acceptance run, run one separately pre-registered 1,800-second live Board
calibration and report back. It tests mixed peers, typed memory, tools, routing, qualified submissions,
instance lifecycle, and cleanup. It does not resolve issue #19, lower acceptance, authorize closure,
or replace the 19,800-second run; the owner will decide whether to authorize that run afterward.
The first calibration used 60-second lanes and falsified that budget. A later diagnostic inverted
the owner's requested budgets. The corrected calibration changed only the competition outer
budget to 1,800 seconds. The qualified all-15 catalogue remains queued, Board-unsolved challenges
first, while five challenge engagements stay active. Recovery and Verifier agents are auxiliary
work inside an active engagement and do not consume one of those five identities. A correct solve
cancels siblings, records the solve, removes and verifies any shared instance, closes the
engagement, then admits the next queued challenge. Per-agent budget remains 800 seconds, P20,
Board request 15 seconds, instance readiness 120 seconds, and cleanup 45 seconds. No successor may
exceed 800 seconds; host-visible tool progress resets only the 600-second no-progress cutoff, not
the absolute lane budget. Merged source and image digest were registered after fresh read-only
qualification and before fresh state creation. Final-acceptance budgets remain pending the owner's
post-calibration decision; its outer gate remains 19,800 seconds.

### E6 current Board inactive semantics

On 2026-09-16, the exact branch-built candidate container performed two authenticated GET-only rounds
over all nine freshly qualified `dynamic_iac` IDs with a ten-second per-request bound. Both rounds
returned coherent HTTP 404, `success=false`, no connection information, and no `until` or `since`
value for every ID; elapsed time was 18.106 seconds and writes were zero. A separate complete
read-only qualification confirmed 15 challenges (nine dynamic, six standard) in 27.5 seconds. This
was independently repeated by Daybreak/xhigh in two more coherent rounds totaling 13.263 seconds,
again with zero writes and the same sanitized shape. This re-establishes the implementation's
fail-closed inactive contract before any instance mutation.

### M1 typed-memory comparison registration

M1 is frozen before implementation or result generation in
[`issue-19-memory-comparison-protocol-v1.json`](issue-19-memory-comparison-protocol-v1.json), SHA-256
`4605399b8ff84acef4ecbcd30bd1856a86b8e3792d94f03fd525db4d70cd8a6e`. It compares exactly two
production projections: `lane_local_v1`, typed earlier-episode analysis and host/controller facts
restricted to the target lane, and `typed_challenge_v1`, bounded eligible earlier episodes from the
same run and challenge across lanes. The latter composes existing SQLite records; it does not add a
database, RAM cache, retained workspace, agent mesh, or candidate-derived prompt field.

The typed projection has six closed record kinds: untrusted analysis claim, host observation,
controller tactic outcome, typed failure, private candidate context, and verification. Arbitrary
analysis prose remains same-lane only. Across lanes, Specialist and Recovery may receive only closed
host/controller fields from earlier episodes. Same-episode peers remain isolated. Verifier receives
fresh source and its recipe only. Candidate context stays controller-private, is excluded from
usefulness scoring, and must join proposal → source attempt → role/route → complete evidence
manifest → a matching successful source-bound observation.

The protocol freezes all 14 fixtures, four insertion permutations, closed public fields,
ordering, greedy truncation, canonical byte accounting, privacy denials, 112 sanitized raw-result
rows, usefulness/duplicate definitions, and raw-derived selector. Both arms receive identical input,
a 64-KiB projection budget, and the existing 128-KiB total prompt cap. The result must come from a
clean merged source using the exact registered command. No Board, native model, network, container,
submission, instance, or target effect is permitted.

Before any accepted result, command-only addendum
[`issue-19-memory-comparison-command-addendum-v1.json`](issue-19-memory-comparison-command-addendum-v1.json),
SHA-256 `756b1e5f0d0b29e1db88db516b9787e6cf70b85d96c99f8bac01786e919da740`, replaced
the unavailable bare `python` executable with `.venv/bin/python`. It changes no fixture, metric,
selector, safety gate, or acceptance rule. The harness requires the exact protocol path, result
path, interpreter, addendum hash, and command.

`typed_challenge_v1` is eligible only with exact replay after reopen; deterministic source ordering;
100% proposal-to-complete-source-context linkage; strictly more useful other-lane records than
`lane_local_v1`; no increase in repeated tactic/observation count; and zero stale, cross-run,
cross-challenge, current-episode, verifier-peer, candidate, digest/encoding, authority, or prompt-cap
violation. A tie keeps `lane_local_v1`. Selection remains provisional until Daybreak/xhigh E4
calibration compares only the memory arm at fixed P4 capacity and preserves oracle correctness while
improving either conversion or duplicate/source-bound work. Only then does E4 vary P2/P4/P6/P8.
M1 cannot lower E4 or final acceptance.

PR #31 squash-merged the M1 implementation as
`84542dbfe4cdb24cb58129b7d2dd0675da541639`. It connects durable attempt/evidence/vault rows to the
registered projection and production prompt builder behind explicit `RAPIDO_MEMORY_ARM` selection.
SQL removes cross-lane model prose before projection; evidence exposes a digest-free typed memory
view; private proposal/verification rows are bounded by the target episode; and candidate
completeness requires a successful source-bound, non-reflected observation. The Verifier projection
is empty while the controller retains private verification state. A changed-route integration
fixture proves both earlier lanes' distinct host facts reach each successor Specialist under
`typed_challenge_v1`. Independent implementation and harness reviews were clean. Local release
validation was 749 passed and one host skip; all four PR checks passed.

The post-merge `main` run exposed the same inherited-`SIGXCPU` failure seen in three earlier main
runs. Resetting the child signal disposition was insufficient because the child also inherited the
parent's blocked signal mask, leaving its self-signal pending and allowing exit 0. PR #32
squash-merged `a592e90d1f0fb38128ec864ce827b496d7b01640`: the artifact worker now unblocks native resource
signals before applying limits, the regression deliberately starts with `SIGXCPU` blocked, and the
M1 writer validates before an atomic no-overwrite install. Local release validation was 753 passed
and one host skip. PR checks and post-merge `main` run
[`35106519460`](https://github.com/jerome-queck/incypher-rapido/actions/runs/35106519460) passed Python
3.11/3.12 and Linux amd64/arm64.

The registered command then generated
[`issue-19-memory-comparison-v1.json`](issue-19-memory-comparison-v1.json) from clean merged source
`a592e90d1f0fb38128ec864ce827b496d7b01640`. Artifact SHA-256 is
`053851cfdb3701da49a4df8e1e87d444162b655a13a053caa8414e5fb5f83400`. All 112 rows, exact ordering,
schema, and insertion permutations passed. Both arms were eligible; `typed_challenge_v1` exposed 48
useful records versus 20 for `lane_local_v1`, with zero repeated fingerprints in either arm, no row
violations, and zero model, network, Board, container, instance, submission, or target effects. An
unchanged rerun failed closed without altering the installed artifact. Independent clean-source
Daybreak/xhigh review independently replayed all rows and commitments, verified 28 source hashes and
the production-tree digest, and found no P0-P3 issue. Selection remains provisional until the
registered fixed-P4 Daybreak/xhigh native comparison passes.

### E0 red-baseline result

`scripts/issue19_replay.py` drives eight sanitized failure representatives through the real
`Orchestrator.run`, prompt builder, evidence projection, `StateStore`, and episode queue over 15
catalogue entries and two episodes. Local fake adapters make network, native inference, Board
writes, submissions, containers, and instance mutation unavailable. The run produced 15 initial
and 15 retry admissions, with every initial admission sequenced before the first retry, and 56
terminal lane/evidence manifests.

The behavior-derived expected-red signal records an unchanged sanctioned route for all 15
challenge retries: 29 lane/preflight comparisons retained the same strategy, tool set, budget,
and deadline policy. All 14 lane-based successor prompts gained automatic prior-episode context,
so their full material input differed; context carry alone is not adaptive routing. The Board case
failed closed before a lane or write. Four synthetic provenance-rejected candidate outputs became
zero retained candidate rows. Four provenance-valid disagreement outputs remained in four private
attempt rows but had no Verifier route. Startup recovery idempotently closed one deliberately
unfinished durable attempt/Run row; it did not resume the same Run, inject an abrupt process crash,
or prove container restart.

SQLite integrity is `ok`; pending submissions, owned instances, new owned async tasks, nested
workspace entries, and workspace symlinks are zero. Descriptor counts are observations only; the
harness explicitly makes no descriptor-identity or leak-absence claim. The test suite treats
successful reproduction as green CI. It deliberately has no prospective production-green gate:
hypothetical report mutations are not durable implementation evidence.

This is a deterministic corpus/replay-schema baseline, not a claim that synthetic counts predict
live conversion. Later implementation must drive the same corpus through its real control Module
and add a separate event-backed green gate from actual durable records without deleting or
rewriting the recorded baseline arm.

### E2 vault and E3 controller comparisons

Daybreak/xhigh exploratory lanes compared a closed table, graph reducer, and scored policy, plus
single-SQLite, file/index, and volatile candidate-retention designs. Their original numeric reports
had no durable source/config/result artifact and remain unaccepted. E3 routing stays pending until
its own reproducible harness exists.

E3 measurement is prospectively frozen by
[`issue-19-routing-comparison-protocol-v1.json`](issue-19-routing-comparison-protocol-v1.json),
SHA-256 `bc7a219c92e893b188584c4567bbb04b97d9be4ffaeaee90aa12d749ce5b5ef6`,
based on merged commit `ae3da51aa675b6fdcfb1cbfe50a33cf5fbc4c954`. No measurement or result
artifact exists at registration. It compares `fifo_unchanged`, `closed_rule_table`,
`graph_reducer`, and `scored_policy` over the same 27 deterministic cases, 20 repetitions, three
episodes, two lanes, exact fixture payloads, complete route templates and budgets, and an
effect-free fixture boundary. Exact policy rules, graph transitions, scoring weights, and canonical
section digests are registered. Policies may select only frozen recipe IDs; common code validates
typed facts, materializes the route, and owns admission. Every failure kind has positive and
negative facts, while mixed, malformed, conflicting, exhausted, duplicate, and persistent inputs
must contain. Policy/runtime inputs exclude the case identity, expected disposition/recipe,
evaluator outcome, arm, and repetition.

Selection is recomputed only from 2,160 strict-schema per-arm/case/repetition raw rows; aggregate
result storage is forbidden. An arm is ineligible for any unsafe,
unchanged, duplicate, divergent, incomplete, leaking, or lifecycle-unclean observation. Among
eligible arms, the unique winner must strictly improve total conversion over FIFO with no
per-kind regression; fixed tie-breaks then prefer minimum tool, context, durable-event,
policy-operation, and canonical policy-config cost. FIFO is a non-selectable comparator whose sole
exemption is the changed/unused-route check; every other authority, privacy, durability, budget,
and lifecycle gate remains. The frozen sensitivity schedule gives FIFO a nonzero 5-of-20
qualification baseline and a correct changed recipe 15-of-20; it tests the selection machinery and
is explicitly not a live-conversion estimate. Ties select nothing. Timing is descriptive only. Label permutation,
synthetic winners for each policy arm, tie/all-ineligible, row/config/digest mutation, and
changed-policy replay are mandatory tamper gates. E1 policy and E6 Board recipes remain
live-locked; fixture facts can never grant live authority. The protocol itself must pass
independent Daybreak/xhigh review and green CI before a comparison result is generated. Result
provenance must bind the clean merged commit, harness and imported fixture hashes, full production
tree digest, exact command/result format, environment, timestamps, and zero disabled-surface calls.

The parent protocol names operation and canonical-config costs but does not define their primitive
units. Before policy implementation or measurement, the exact units are separately frozen in
[`issue-19-routing-operation-count-protocol-v1.json`](issue-19-routing-operation-count-protocol-v1.json),
SHA-256 `c7e5147fbe9d4367b9f4bc40850faf3011c50d0d586ee22a69f3d792726e75bf`,
bound to the parent protocol SHA and merged base `ecee4aec53e609fb2941548d9716171580eef2ea`.
It excludes common validation/materialization/SQLite/evaluator work and fixes every table rule
visit, graph fold/edge visit, scored-recipe visit, fact lookup, score action, and comparator action.
It also freezes pre-policy and post-policy gate order: 19 exact cases invoke a policy, while eight
early-contained cases record zero policy operations; canonical config bytes remain recorded for
every row. The harness must import and provenance-hash this addendum; raw costs are recomputed and
tamper-gated. Exact per-arm config byte constants, context/event accounting, replay fields and
exclusions, null/type and FIFO-flag semantics, result-container schema, input-derived invocation
predicate, and full-protocol operation totals are also fixed.

The E3 implementation squash-merged in PR #28 as `093925e781c4bfd80d38b5108c1db01576f61296`.
Its 30-test suite covers the full 2,160-row registered operation totals, raw arm
permutation/synthetic winners/ties, direct native-socket and child-process blocking, new-thread
profiling, decision/fact/route tamper rejection, rollback injection, and a real `os._exit(73)`
transaction crash followed by clean recovery. The first Python 3.11 CI run exposed retained heap
noise from a non-removable audit hook in the shared test process. The merged fix keeps reversible
profiling and entry-point fences for imports/tests, and installs strong alias-proof audit
interception only in the disposable canonical process. Local release verification was 709 passed
and one skipped; rerun CI passed Python 3.11/3.12 and Linux amd64/arm64.

The preregistered command then generated
[`issue-19-routing-policy-comparison-v1.json`](issue-19-routing-policy-comparison-v1.json) from that
clean merged source. Artifact SHA-256 is
`491401dd71f9c2209bad332703f002839292c6904c04d886313bdf0dca76501f`. All 2,160 rows and exact
operation totals replayed; `closed_rule_table` won the frozen selector after the three eligible
policies tied on safety, conversion, unproductive dispatch, tool count, context bytes, and durable
event bytes, because it used 5,120 policy operations versus 7,500 and 8,440. FIFO was ineligible.
Every disabled-surface, effect, instance, residue, and leak counter is zero. Independent
Daybreak/xhigh review verified all 27 merged-source hashes, raw selection, replay/config/fact
digests, privacy, and 30/30 focused tests with no blocker. This is development E3 evidence only;
live-controller promotion and every final-image/live gate remain pending.

The implementation uses the smallest fail-closed shape: exactly eight failure kinds, two
dispositions (`dispatch` or `contain`), immutable model/effort/effect authority, and a unique
material route fingerprint. Policy, provenance, and Board failures remain contained. Durable
candidate disagreement may dispatch an exact Verifier; quota may earn one bounded wait; tool and
safely identified local-container failures may dispatch one changed route. A timeout may earn one
changed Recovery only when its source wave committed observations and budget/effect/instance gates
remain safe. A repeated or zero-evidence timeout remains contained. Persistent failures cannot use
episode, timestamp, or retry ordinal alone as change.

E2 now has a reproducible, effect-free storage-subdecision candidate at
`scripts/issue19_vault_comparison.py`, with the exact sanitized result in
`notes/research/issue-19-vault-comparison-v1.json` (SHA-256
`1ad4b10786e3bcbd59c75b82b3c2cd5c401f9a90f94519ebb96eedcf7c7927f0`). It runs 11
same-process, reopen, rollback, three real `os._exit(91)` crash-point, replay/conflict, peer,
scope, privacy, and filesystem cases for each of three adapters. Metrics are recomputed from case
rows after exact adapter/case schema and raw invariant validation. Selection cost is recomputed from
raw storage observations; five normalized full replays are identical; altered rows, costs, schemas,
and every safety class fail the gate. The artifact records the base commit, fixture, script digest,
pretty-output command/format, elapsed observation, Python/SQLite/platform, filesystem block sizes,
permissions, and SQLite durability settings.

SQLite and file/index both had zero acknowledged loss, ghost commitment, conflict acceptance,
duplicate record, peer loss, scope bypass, public leak, reconciled residue, unsafe entry, or
integrity failure. Volatile storage lost two acknowledged records across reopen/post-commit crash
and was disqualified. File/index needed two orphan-reconciliation actions and two durability
domains; SQLite needed zero and one. Development storage observations were 225,280 and 270,608
bytes respectively. The safety-first requirement was fixed, but the domain/action/bytes tie-break
was written after these measurements and is therefore post-observation, not pre-registered. It
provisionally selects the single SQLite transaction domain. Timing is deliberately not a decision
metric. Independent Daybreak re-review is clean. A prospective Linux final-image replay remains
required before treating this storage subdecision as accepted; full E2 still must compare admission
behavior, not only persistence.

The first E2 behavior artifact was rejected by independent Daybreak review and removed: it gave the
arms unequal episode budgets, inferred legacy admission through raw SQL, used an in-memory answer
oracle rather than an artifact, hard-coded the selected arm, and identified only the pre-change
base. No result from that run is accepted.

The replacement is reproducible at `scripts/issue19_candidate_flow_comparison.py`; its exact
20-repetition sanitized result is
`notes/research/issue-19-candidate-flow-comparison-v2.json` (SHA-256
`301b3f9cbf963bb466f9b5d0d41ab2c334078f8e046c85089db901e1a027d42d`). It drives the
production orchestrator and durable controller through equal two-episode/two-lane budgets over
peer agreement, one useful lane plus one failed peer, challenge-description decoy, distinct source
candidates, verifier mismatch, and model-input reflection. Each lane gets a fresh copied JSON
artifact; the fake runtime has no Board-answer reference and derives its output only from that lane
artifact or, for the decoy negative, the public challenge description. Admission is measured for
both arms only through the production submission path against a local deterministic Board fake.
No network, external Board, container, or model effect is enabled.

All 240 raw rows include exact arm/case/repetition identity, observed per-run elapsed time and tool
cost, actual local admission, report outcomes, provenance failures, private aggregate counts,
route/Verifier activity, prompt leakage, and exact configured model/effort. Raw schema, order,
safety relations, and negative-case invariants are checked before arm summaries are derived.
Selection is the unique eligible arm with the greatest positive-case conversion, plus a fixed gate
requiring both failed-peer and source-disagreement conversion; tampered safety, timing, model,
admission, order, schema, or a conversion tie fails. Provenance records exact per-arm configuration,
base commit, script SHA-256, and every production source-file SHA-256 with aggregate source-tree
SHA-256 `f1e2becc0d438a1b709483af54e78f1943cb1f1f018339e93f6ab0827742cc79`.

The exact-agreement arm qualified only peer agreement. The private-verification arm also converted
the failed-peer and source-disagreement cases after fresh deterministic re-observation, while the
decoy, reflected input, and verifier mismatch remained unqualified. Across every row it had zero
false admissions, candidate prompt leaks, or model/effort mismatches. The 20 repetitions produced
20 versus 60 correct local admissions, 440 versus 400 observed tool calls, and 2.385544 versus
2.302042 aggregate observed seconds for exact agreement and private verification respectively;
timing is recorded but not selected on. The candidate
value and common raw, digest, hex, base64, base64url, and URL encodings are absent from the artifact.
The corrected registered criterion therefore selects private verification with the single-SQLite
vault and `fresh_source_reobservation_v1` recipe. Independent Daybreak/xhigh re-review reproduced
the 20-repetition v2 artifact/source hashes and found no P0-P3 defects. Linux final-image replay
remains a release gate; this result makes no live-conversion claim.

A post-implementation v3 compatibility replay is stored at
`notes/research/issue-19-candidate-flow-comparison-v3.json` (SHA-256
`a56fce03b56476e65906c0d9c7beeabbc4c12f4c8b8ee365eac7cda1b1e683f9`). This is a regression
check, not a retrospective replacement for the registered v2 architecture decision. Its 240 raw
observations bind the current production tree SHA-256
`95bfa59d84d190a9079cfc8624d5102381cf018835fd6ddce679b1b0ea14ab95`. Exact agreement converted
20 cases with 440 tool calls; private verification converted 60 with 320 tool calls. Both had zero
false admissions, prompt leaks, or model/effort mismatches, and the gate again selected
`private_verification`.

The implementation keeps durable candidate bytes and keys only in run/challenge-scoped private
SQLite records. Specialist or Recovery proposals bind by database foreign keys to the immutable source attempt and a
source-observation recipe. Verifier proposals bind by composite foreign keys to the exact same-run,
same-challenge producer scope and use a fresh source-only prompt with no peer prose or candidate
carry. Incomplete or malformed host evidence rejects the candidate before retention. Candidate
attempt prose is replaced structurally, and public wave/withholding events omit candidate-derived
identifiers. Attempt closure plus retention/verification is one transaction. Real producer and
Verifier pre-commit/post-commit process exits, injected rollback, replay conflict, cross-challenge
swap, prior-run reuse, failed-peer retention, verifier mismatch, description decoy, and
reflected-input tests cover the fail-closed boundary. Every Verifier wave completes; multiple
verified identities are contained independent of completion order. Only the effect-owning
controller can retrieve one unambiguous verified value for admission; public control views expose
aggregate counts only.

Candidate-flow local validation after review fixes: Ruff/format/`git diff --check` clean; 669 passed
and 1 skipped on dependency-complete Python 3.11 and 3.12 environments. A first Python
3.12 environment lacked installed parser dependencies, and a second had those dependencies but no
isolated-mode Rapido install; neither result is counted as a product failure or green validation.

Exactly-once Board POST remains impossible without remote idempotency; the current enforceable
boundary is durable at-most-once reservation plus fenced ambiguity. The comparison claims interface
confinement, not secrecy from same-UID/root access, and does not test power-loss durability.

## Selected architecture contract

- **Lead:** deterministic controller projection chooses the next typed engagement from durable
  facts. It cannot submit, delete, or widen authority through model text.
- **Specialist:** fresh bounded analysis lane with one declared tactic/tool family and immutable
  source/target scope. Its output is a typed finding plus host observations.
- **Verifier:** independently re-observes a retained private candidate using a deterministic,
  source-bound recipe. It receives neither another lane's prose nor effect authority.
- **Recovery:** maps a typed failure fingerprint to a materially different sanctioned route,
  bounded backoff/probe, or terminal containment. Re-entry requires a changed route fingerprint.
- **Typed memory:** run/challenge scoped records for observations, tactics, hypotheses, failures,
  retained private candidates, verification recipes/results, queue decisions, budgets, and effect
  identities. Cross-lane views expose only allowlisted facts; private candidate bytes never enter
  peer prompts or repository evidence.
- **Replayable queue:** every admission has a stable key, reason, role, route fingerprint, source
  fact IDs, budget, deadline, and sequence. Initial coverage outranks retry; evidence-backed
  progress may earn a bounded extension that cannot consume another challenge's initial coverage
  or cross the run deadline.
- **Effects:** Board submissions remain serialized and crash-durably reserved before POST;
  ambiguous outcomes fence the candidate. Instance mutation remains receipt-bound and fails closed
  on indeterminate state.

## Delivery slices

1. Red baseline: execution brief, deterministic failure corpus, replay signal, and measured current
   behavior.
2. Core implementation: typed memory, failure taxonomy/router, role engagements, private vault,
   deterministic verifier, replayable scheduling, and recovery state.
3. Focused tests and controlled comparisons: security negatives, crash/fault matrix, resource
   scaling, native non-submission calibration, Board contract fixtures.
4. Independent Daybreak/xhigh review of each material slice; findings fixed before green CI and
   squash merge.
5. Final-image preflight and protocol registration; fresh unattended acceptance; sanitized
   evidence PR; cleanup verification; honest #19 closeout.

Each focused PR must preserve unrelated work, pass Python 3.11/3.12 and Linux AMD64/ARM64 CI, and
be squash-merged only after independent review is resolved.

### Core implementation tracer: durable job journal

The first core tracer adds the public `DurableJobControl.drive(config, board=..., runtime=...)`
and `DurableJobControl.inspect(state_path, run_id=None)` seams. The existing Board and runtime
interfaces remain the only effect boundaries. Complete per-run catalogue membership plus initial
Specialist lane identities, catalogue rank, episode, material route fingerprint, truthful lane
terminal, and admitted/started/closed event sequences are written in the same SQLite transaction
domain as run state. Inspection uses one read transaction and returns only sanitized job and run
metadata; retained solver candidates and their digests are deliberately absent. Pending Board
effects and owned instances are intentionally state-wide safety counts, even while inspecting a
prior run.

The tracer established a measured substrate, not the final scheduler: the existing orchestrator
still owns execution order, while private retention and independent verification were subsequently
added in E2; durable queue authority and same-run recovery remain later red/green tracers. Public boundary tests
prove sanitized round-trip inspection; stable order across reopened inspection; unchanged-route
identity across episodes; material-route separation; live queued/running projection; graceful
deadline closure; and process-loss recovery after a real `os._exit`. This recovery preserves a
lane terminal committed immediately before process loss, interrupts only unfinished jobs, and
closes the lost run before starting a new run; it does not yet resume the same run. The first
independent Daybreak/xhigh review found five P1 defects and one P2 overclaim. Re-review found one
further P1 terminal-overwrite crash window. All were addressed test-first. A third Daybreak/xhigh
release review found no P0-P3 defects; CI remains the release gate.

Local release validation: Ruff and `git diff --check` clean; 604 passed and 1 skipped on both
Python 3.11 and 3.12.

### Adaptive failure-router tracer

`DurableJobControl.drive` now enables a closed adaptive path while direct `Orchestrator.run`
retains the empirical red-baseline behavior. Exactly eight candidate-free failure signals cover
policy, provenance, disagreement, timeout, tool, quota, Board, and container outcomes. Board and
container origins are recorded at their catch boundaries instead of inferred from challenge type.
Authorization and unclassified native failures fail closed. A tool failure can dispatch one
alternate tactic/context; a safely typed local-container failure can dispatch one Recovery role in
a workspace path bound to its generation. No other route dispatches until a later slice supplies a
database-validated prerequisite. Generic unsolved analysis is contained rather than mislabeled.

Routes have one durable JSON authority in `control_routes`; jobs reference it by a composite
foreign key. Wave closure, failure classification, decision recording, and successor admission
commit in one SQLite transaction. A fault-injected admission failure proves the prior wave remains
running and no partial decision survives. Public inspection feature-detects the preceding schema,
validates decision enums/axes, and exposes only base64url-labelled fingerprints. The E0 production
fixture proves all eight signals, material changes for every dispatch, no unchanged third attempt,
and no candidate value or digest in public output. The original review rejected eight P1 and three
P2 defects; the first re-review found two further P1 defects and one P2 vocabulary drift. A later
review rejected a false-positive combined-failure fixture before accepting its corrected sequence.
All are covered by focused regression tests; final Daybreak/xhigh review found no P0-P3 defects.

Local validation after repairs: Ruff/format/`git diff --check` clean; 633 passed and 1 skipped on
Python 3.11 and 3.12. E3 outcome comparison remains a separate pending gate; E2 storage passed
independent review but awaits final-image replay, and E2 admission is implemented with local
comparison green while independent review is pending.

## Acceptance ledger

| Requirement | Evidence required | Status |
| --- | --- | --- |
| Required sources and predecessor inspected | This brief plus source note and cited paths | complete |
| Controlled architecture selection | Three-Interface comparison plus E0-E3; closed-core hybrid recorded | in progress: Interface selected; E2 selects private single-SQLite verification; clean-source E3 selects the closed rule table; final-image replay pending |
| Adaptive failure routing; no unchanged retry | Replay fixtures and route-fingerprint assertions | in progress: gap-specific same-chat correction plus one evidence-earned changed timeout Recovery implemented and focused locally; final live proof pending |
| Lead/Specialist/Verifier/Recovery cooperation | Typed engagement/replay tests | in progress: clean one-hour rerun exercised all roles and nonempty Recovery memory; hard-timeout Recovery now uses three Daybreak plus one Luna without increasing four-peer concurrency; final proof pending |
| Private candidate retention and verification | Vault isolation, deterministic admission, false-positive tests | in progress: transactional same-run vault, unique exact verification, producer/Verifier crash and privacy/false-positive tests, corrected 20-repetition E2 comparison, and clean review green; final-image replay pending |
| Replayable ordering, extensions, 15/15 coverage | Queue replay/crash tests and final-run evidence | in progress: durable focus order, evidence-scaled 800–1,800s grants, 600s admission floor, derived instance park/wake queue, and same-deadline Board watcher implemented locally; final live coverage pending |
| Productive bounded resource scaling | E4 measurements and selected profile | in progress: prior E4 selected 8 native tool workers/P20 at 7.568 cores, 16.20 GB, and 188/256 PIDs; current 14-CPU host now exposes 12 container CPUs while retaining two host CPUs, but live sampler evidence is pending |
| Crash-safe 19,800-second recovery | E5 plus final-run/restart evidence | in progress: exact merged image verified through real process loss, same-run continuation, private candidate retention, changed verification, original deadline, durable ordering/memory, effect fencing, and cleanup; final live proof pending |
| Board inactive semantics established | E6 independent evidence | complete: two coherent zero-write HTTP-404 rounds across all nine dynamic IDs |
| Exact final image/protocol registered before state creation | Issue comment and immutable digest/source | corrected 1,800-second calibration complete; final 19,800-second registration pending |
| Fresh unattended all-15 run; >=1 new `correct`; cumulative >=4 | Sanitized exact-run evidence | pending final run; clean one-hour rerun started all 15 and added Combination, but was diagnostic-only |
| New mechanism materially contributed | Source-bound route/verification trace, sanitized | pending final run; one-hour correct was initial and does not satisfy this gate; timeout Recovery must prove live contribution |
| No steering/fallback/pending/indeterminate/leak/regression | Audit, review, CI, Board and cleanup checks | one-hour rerun independently clean except its raw resource sampler was not durably retained; final proof pending |
| Exact run state deleted after evidence merge; auth preserved | Targeted post-deletion inspection | complete for corrected calibration; final run pending |
| #19 closed honestly | GitHub closeout linked to merged evidence | pending |

### Mixed-peer live calibration result

The separately registered Board calibration completed on 2026-09-17. It covered all 15 challenges,
enforced the exact Daybreak-plus-Luna roster under a P20 cap (observed P16 peak), committed 1,093
tool observations, retained a
private candidate after partial peer success, dispatched four fresh Daybreak Verifiers, retried no
unchanged route, and cleaned ten dynamic cycles. It produced zero verified candidates and zero
submissions: the producer identity and independently agreed Verifier identity differed. Fifty-eight
of 60 initial lanes timed out under the calibration-only 60-second deadline, falsifying that setting
for solve quality. Typed memory projected safely but supplied no records in this episode shape.
Independent post-run Board and local audits were clean. Full sanitized evidence is in
[`issue-19-calibration-evidence-2026-09-17.md`](issue-19-calibration-evidence-2026-09-17.md).

### Production-path 800-second calibration result

The diagnostic calibration used an 800-second outer ceiling and 1,800-second lanes, inverting the
owner's intended 1,800-second outer run and 800-second agent budget. It failed its registered 3/5
checkpoint with zero solves. Five
dynamic-first challenge workers claimed active slots before the one-slot dynamic semaphore, so only
one challenge and four model attempts actually executed. Three agents produced the same private,
source-bound candidate after 166 committed tool observations. Whole-wave blocking and the absence of
an immediate unverified-candidate branch made no submission before deadline. Typed memory again
projected zero records because no follow-on episode started. Instance, container, Board, and
workspace cleanup were clean; DB integrity was clean, but exact state deletion remains pending.

This selects four focused changes before another performance run: measure rather than assume the
Board's dynamic limit; add a unified manager so every challenge can do local work while one shared
instance per dynamic challenge is leased only for its live phase; submit source-qualified candidates
immediately when the Board exposes no attempt limit; and feed local results into instance-enabled and
Recovery agents as nonzero typed peer memory. The implementation slice also needs truthful job state,
a no-progress watchdog, role-specific successor lanes, sibling cancellation on `correct`, and early
instance release. Full sanitized evidence is in
[`issue-19-production-calibration-evidence-2026-09-17.md`](issue-19-production-calibration-evidence-2026-09-17.md).

### Dynamic capacity and corrected live-path decision

A Board-only changed-control ladder established the current team boundary before this patch: one
dynamic instance reached ready state, while adding a second distinct challenge failed. Each second
challenge then reached ready state alone; a changed pair again failed at level two. Every touched
instance was removed and two final all-nine reads were inactive. The selected bound is therefore
one live instance, not a guessed container limit.

The next-run scheduler keeps five challenge waves active locally and launches four direct peers
per wave (two Daybreak/xhigh Leads plus Luna max/xhigh Specialists). A dynamic episode starts as
artifact/local analysis with no Board mutation. Its changed Recovery route enters a single unified
lease, starts durable jobs only after lease grant, creates one instance shared by all four peers,
and deletes it before release. All dynamic initial phases close before any live lease; live tickets
then follow durable episode/catalogue order. Indeterminate cleanup poisons the manager and fails the
run before another live job starts.

The shared-instance Recovery prompt must contain nonempty typed earlier-episode memory. Unlimited
challenges submit each distinct source-qualified candidate immediately through the fifth wrong via
durable reserve/POST/finalize; `correct` cancels siblings and triggers early instance deletion.
Limited challenges require one fresh Daybreak verifier. After five HTTP-200 wrong verdicts, a
fresh-source Daybreak Verifier must independently reproduce the next candidate before submission.
Pending or unread
effects fence every later submission. The global artificial wrong ceiling was removed; Board limits
remain authoritative. Every lane is capped at 800 seconds; a lane with no host-visible tool progress
for 600 seconds is interrupted and classified for a changed route. The exact-image calibration
verified this control path live and exposed the persistent-Daybreak/provenance work recorded below.

### Owner constraint recorded during the corrected calibration

This applies to the next implementation/run and does not alter the frozen calibration image or
protocol. Daybreak/xhigh is each challenge's primary solver as well as its Lead. A Daybreak turn
that returns before its cumulative 800-second challenge budget without `correct` must continue in
the same native conversation with a changed, evidence-specific prompt. Continue until `correct`,
the cumulative budget expires, or a genuine terminal blocker is proven. In particular, a
candidate-provenance rejection must stay in the same conversation but follow its exact gap:
re-observe an unobserved hypothesis, abandon an ineligible decoy, or derive afresh after supplied or
incomplete evidence. Luna peers remain parallel supporting
solvers. Continuations must preserve private state and typed memory, consume the original budget,
and never repeat an unchanged prompt. The global deterministic coordinator remains outside the five
challenge engagements and P20 solver lanes; any future model coordinator is auxiliary and must earn
its cost in a controlled comparison.

### Corrected 30-minute calibration result

The registered exact-image run completed with two new HTTP-200 `correct` solves, both produced by
Daybreak/xhigh Recovery lanes after nonzero typed-memory projection and shared-instance routing.
Immediate submission, sibling cancellation, instance removal, and lease transfer worked. Peak
running attempts reached P20 across the initial five engagements. The initial-five 0/5 result
failed the fixed 3/5 diagnostic checkpoint; 14 plausible hypotheses were lost to provenance
enforcement, and non-correct Daybreak turns ended after a median 65.233 seconds instead of consuming
their remaining budget. Full facts and next fixes are in
[`issue-19-corrected-calibration-evidence-2026-09-17.md`](issue-19-corrected-calibration-evidence-2026-09-17.md).
This run does not replace the 19,800-second acceptance run.

### Persistent-primary implementation decision

The controlled diagnosis selected a small extension of the existing race, not a new coordinator.
One Daybreak Lead/Recovery lane now owns one Codex thread across multiple turns under its original
cumulative deadline during standard or shared-instance work. Dynamic local-only completion hands off
immediately so it cannot idle the instance lease. Early `unsolved`, `unsupported`, malformed-output, and four distinct provenance
gaps receive candidate-free changed prompts; a qualified candidate returns immediately for the
existing submit/cancel/cleanup/advance path. Luna lanes remain parallel one-turn racers. Tool evidence
accumulates for the attempt while candidate qualification uses the current proof turn, preventing an
earlier incomplete checkpoint from poisoning a later fresh observation. Existing `derive_artifact`
content-addressed paths are now explicitly required for artifact range decoding instead of copying
source bytes into model-supplied transforms. Focused tests cover same-thread reuse, shrinking budget,
each corrective prompt, and source-bound conversion. Final live contribution remains unproven.

### Same-run process-loss comparison and implementation decision

Three independent Daybreak/xhigh reviews compared a separate recovery subsystem, a minimal
same-state reopening seam, and reuse of the existing durable controller journal. The selected
design reuses the existing run, catalogue, jobs, routes, attempts, events, typed memory, candidate
vault, submission intents, and instance receipts. It adds no second scheduler or effect journal.
On lease reacquisition, the store atomically identifies the sole `running` run, requires the exact
public configuration, closes only process-lost running work, and admits one changed
`process_restart` Recovery route. Reopening is idempotent and retains the original wall-clock start
and deadline; downtime never earns more solve time.

The initial catalogue and every episode-zero admission now commit in one transaction. Restart
replays untouched episode-zero work before interrupted successors, preserves closed lanes and
typed same-run memory, and compensates the episode ceiling only for proven process-restart
dispatches. Every completed persistent-primary checkpoint durably retains candidate-free analysis,
next steps, tool count, and sanitized host observations for the changed Recovery route. A qualified
candidate is also committed to the private vault inside the callback before control returns to the
runtime, closing the crash window between Daybreak discovery and normal attempt completion. Stable
Board identity plus qualified metadata and attachment-content identities are rechecked while
durable catalogue ranks remain authoritative. Before workspace cleanup or model startup, instances
are reconciled under an independent bound. A receipt mismatch remains fenced; a receiptless active
generation is never adopted or deleted because the Board offers no generation token that proves it
belongs to the persisted create intent. An
ambiguous submission fences only its challenge while unaffected work continues, then keeps the run
open for explicit reconciliation; the candidate is never posted twice. An expired restart performs
reconciliation and cleanup but admits no solver work; fully closed durable work finalizes without a
runtime or catalogue fetch, while a pending submission keeps even an expired run open.

Focused evidence includes real subprocess `os._exit(23)` cases after both candidate-free and
qualified-candidate Daybreak checkpoints,
same-run ID/deadline preservation, repeated pre-attempt restart routing, untouched-before-retry
ordering, recovered checkpoint/host-observation memory, correct-intent reconciliation, configuration
and challenge-material mismatch rejection, terminal fast-path completion, unaffected progress beside
a pending effect, expiry without solver start, receiptless create-intent fencing, successful receipt
cleanup, and mismatched-receipt containment. Ruff, 178 focused tests, and the full 796-passed/1-skipped
suite are clean. The acceptance run remains pending.

### Exact-image recovery rehearsal

After PR #42 merged, commit `b1c235b21f74964876ab17c05ed63f627d7caabe` built locally for
Linux ARM64 as `sha256:95a1399e36ec492afbdafeb54c3d32b8abe15bf7a7b247f2f3a1f9f6ba9f2ac9`.
Codex reported `0.154.0`; the offline tooling acceptance passed under the competition CPU, memory,
PID, read-only-root, tmpfs, dropped-capability, and no-new-privileges bounds with networking
disabled.

A separate no-network rehearsal used one fresh named state volume and no auth or Board credential.
The first container called real `os._exit(23)` immediately after a source-bound Daybreak candidate
was committed by the continuation callback. A second container using the same exact image and
volume reopened the same run, retained one private candidate, dispatched one Verifier, completed
both synthetic challenges, closed every durable job, and reported zero Board writes, pending
submissions, and owned instances. This proves the merged recovery mechanism inside the production
image; it is not a live solve or a substitute for the 19,800-second acceptance run.
After this sanitized record was pushed, the exact rehearsal volume and container names were absent;
the image was retained, and no authentication state existed to preserve or remove.

### Current local launch readiness

Before further live work on 2026-09-17, the local `rapido:local` tag still referenced the older
pre-fix image even though the merged `2810059` image was already present. The tag was moved to that
existing image (`sha256:078c81376f391504d72d6f9f0775ff76e942c05bbade4701f4f78e638241b23e`)
without rebuilding. A containerized configuration assertion then confirmed the selected competition
profile: five active challenges, four peers each, P20, 800-second lanes, three episodes, and a
19,800-second run ceiling. A separate authenticated preflight returned all 15 challenges with zero
Board writes. This is local readiness evidence, not final preregistration: the final run must still
name an immutable image digest and merged source before its fresh state exists.

### `ctf-workspace` solving-framework audit

The public framework was inspected read-only at commit
[`4631053`](https://github.com/jerome-queck/ctf-workspace/tree/463105313f82817d74cc0df67a648b3e698d3b10).
Its strongest supported mechanism is structural persistence: prompt-only attempts exited early,
whereas the launcher resumes the exact native Codex session under one ceiling
([ADR 0037](https://github.com/jerome-queck/ctf-workspace/blob/463105313f82817d74cc0df67a648b3e698d3b10/docs/adr/0037-persistent-attempt-launcher-resume.md)).
Per-challenge attempt trees preserve scripts, findings, and dead ends. Workload-specific native
tools also mattered in individual solve histories. Conversely, the standard launcher prompt is
long, broad tool count has no controlled solve-rate evidence, and the framework recommends agent
fan-out mainly for the hardest tiers. Therefore Rapido will not import its prompt, agent mesh,
sweep state, or wholesale image.

Autonomous derivation was assessed separately from manual platform submission: retained scripts and
attempt histories support autonomous solver contribution even where a status board says
`solved_by: user`. The defensible transfer is a thin controller, a short outcome-first initial task,
exact-session continuation, durable challenge-local work, selective typed context, and targeted
tools proved against fixtures. The initial prompt and capability context will be varied separately;
the framework does not establish that an instruction-free first pass is superior. Full hypotheses
and experiments are recorded in
[`issue-19-long-horizon-agent-research-2026-09-17.md`](issue-19-long-horizon-agent-research-2026-09-17.md).

### Candidate evidence authority repair

The recovery path had retained a candidate before its producer evidence was known complete. A
Verifier could later match that identity even when the producer manifest was interrupted or empty.
The repair adds an immutable, candidate-specific proof binding each running attempt to the exact
committed manifest digest only after a successful source-bound observation contains that candidate,
with no supplied occurrence, omission, or gap. Verification now requires matching producer and
Verifier proofs and manifests. Every public/private candidate-authority read ignores legacy rows
without both proofs; a later valid verification removes a stale same-candidate row first. Regressions
cover interrupted checkpoints, empty manifests, legacy invalid rows, and observations dropped by
post-normalization quota. Independent Daybreak/xhigh review was clean; Ruff and format are clean,
and the full local suite passes 799 with one skip. Container/CI evidence remains pending.

### Challenge-native analysis capability

The corrected calibration showed a more basic solve-quality limit than agent count: peers could
call fixed inspection tools but could not write and execute their own solver programs. Historical
`ctf-workspace` solve paths were therefore audited through current and pre-purge commits instead of
copying its install inventory. The resulting
[`issue-19-ctf-workspace-tool-evidence-2026-09-17.md`](issue-19-ctf-workspace-tool-evidence-2026-09-17.md)
contains 75 immutable source links and distinguishes tools that contributed to successful
derivations from paper-installed, unsuccessful, architecture-specific, or unrelated stacks.

The selected implementation adds one general challenge-local Bash capability rather than a wrapper
per utility. A lane may read its challenge workspace, create and execute persistent scripts only in
`rapido-analysis`, and use the evidence-backed crypto, math, pwn, reverse, forensics, packet, archive,
media, PDF, and Android toolchain. Each call names one or more controller-provided challenge inputs;
the controller durably records their hashes, the command hash, bounded execution facts, and resource
use. Shell output qualifies only when its host receipt binds the command to controller-provided
challenge inputs, contains the candidate without receiving it as input, and has no incomplete
provenance. Such candidates may use the unlimited-challenge immediate path through the fifth wrong;
limited or later candidates require a fresh Verifier to obtain the same candidate through a
non-shell fixed source/target receipt. Model-created `rapido-analysis` files cannot become source roots through a later inspector or
decoder. Exact-session continuations retain the `rapido-analysis` work and typed same-run findings.

The shell is a fixed child boundary, not the credential-bearing Codex process. Landlock hides
authentication and sibling state, makes the challenge root read-only, and confines writes and
execution to `rapido-analysis`; seccomp denies networking and supervisor-control syscalls. CPU,
output, file, descriptor, command, timeout, process-group RSS/task, and global-worker bounds remain explicit. Live
interaction continues through the challenge-bound HTTP/TCP tools, preserving target allowlisting.
The worker cap is eight concurrent local analyses with a 2 GiB process-group RSS watchdog each. Actual
RSS, not summed address-space ceilings, controls safe concurrency; capacity is reserved for the P20
agents and controller. This is a capacity ceiling, not a RAM-use claim.

The offline E4 pressure protocol compared 4, 6, and 8 native-tool slots under the exact
8 CPU/24 GiB/256 PID envelope while retaining five challenges and P20 solver admission. It runs
three mixed Ghidra/JADX/Sage/angr/Hashcat/OpenCV/FFmpeg/forensics rounds per profile, held memory
and PID phases, adversarial address-space/process-tree gates, and exact cleanup checks. The earlier
receipt was invalidated when review changed the measured worker and sandbox source. The exact rerun
used committed source `9a33d6642b31ee756b76fa140e5ca4a6015babef` and image
`sha256:0af9bb4fd6a06cfda4cc314db39b0b7eb34d8111267decbfbe5694acfacdfc3e`.
All P4/P6/P8 mixed, held-memory, held-PID, P20 admission, changed-follow-up, adversarial,
source-immutability, sampler, cgroup-event, and cleanup gates passed in 381.821 seconds. P8 is the
selected native-tool ceiling: mixed work peaked at 7.568 CPU cores; the held phase peaked at
16,197,509,120 bytes and 188 PIDs; all memory/PID/OOM event deltas were zero; tracked groups,
temporary state, child processes, threads, and file descriptors returned exactly to baseline. The
sanitized receipt is
[`issue-19-tool-pressure-evidence-2026-09-17.json`](issue-19-tool-pressure-evidence-2026-09-17.json),
SHA-256 `1bcac3725a7ce7a5ee9fb6810069842c8a6971b09f6dd15c248f15d8265cd254`.

A pre-live repetition on merged scheduler commit `eea3875ee9af025e3704737ec30fbf393917b796`
and image `sha256:486c6ed88e5154ff0a55e3265029040b38004e4e0033361aabe0ffa7328517da`
found one real P8 boundary: Ghidra failed its JDK probe in two of three eight-way mixed rounds,
although P4/P6, a fresh P8 lane, held memory/PID phases, every other tool, cgroup events, and exact
cleanup were green. A 33-second isolated P8 loop reproduced it; three sequential Ghidra calls did
not. Pinning Ghidra's configured JDK did not help. The evidence isolated the failure to
`RLIMIT_NPROC=192`: Linux counts that limit across every process and thread sharing UID 10001, so
the Java probe lost its next child
before the 256-PID container fence. Raising only the worker/descendant ceiling to 224 made the same
P8 loop green at 182 PIDs. The 192-PID new-tool admission fence and 256-PID cgroup hard stop remain.
An exact committed-image full pressure rerun is required before live registration.

The exact final-container receipt must compile and run a solver program; exercise representative
Python, Sage, angr, Ghidra, JADX, GDB static/QEMU execution, packet, forensic, archive, media, PDF, and CPU-hashcat
operations; prove script persistence; and prove credential/sibling-state writes, networking,
supervisor signalling, and leaked descendants fail. Presence-only version checks do not pass. The
final committed-source ARM64 image passed both tmpfs and realistic bind-mounted state after all
review fixes, including real Ghidra `main` decompilation, FFmpeg frame extraction, SleuthKit recovery,
malformed-PDF detection, exact lattice/relocation work, CPU hashcat, confinement, and exact cleanup.
The full local suite passes 827 with one skip; Ruff, format, and diff checks are clean. Independent
review found no remaining P0-P3 findings. Fresh AMD64 acceptance, dual-architecture CI, and live solve
contribution remain pending.

### First one-hour diagnostic and changed next-run control

The exact registered run from merged source `62909ac` started all 15 engagements and produced six
new HTTP-200 `correct` solves before failing at 44 minutes. Four corrects came from changed Recovery
episodes with nonzero typed memory; two came from initial Daybreak lanes. It exercised 28 same-chat
Daybreak continuations, immediate submission, correct-triggered sibling cancellation, five complete
instance create/delete cycles, and zero pending effects. It is not a successful one-hour lifecycle
run: a Daybreak Recovery lane reached 133 cumulative tools, evidence retained only 100, the terminal
counter rejected 133, and one attempt remained incorrectly `running`. Full sanitized evidence is
in [`issue-19-one-hour-diagnostic-evidence-2026-09-17.md`](issue-19-one-hour-diagnostic-evidence-2026-09-17.md).

Before a fresh rerun, the owner directed solve conversion over conservative post-wrong gating. The
selected light change removes the artificial terminal tool-count ceiling, raises immutable evidence
capacity to 10,000 observations/64 MiB per lane, and terminalizes orphan attempts on fatal shutdown.
At the measured 133 observations per 803 seconds, the observation ceiling exceeds eight times the
projection for the maximum configurable 7,200-second lane; actual bytes are stored, not preallocated.

The diagnostic's model split was decisive enough for the next calibration: Daybreak produced 10
candidates and five corrects across 25 terminal attempts, while Luna produced three candidates and
one correct across 66. With at most five percent observed quota movement, the next roster is two
Daybreak/xhigh and two Luna max/xhigh racers per challenge under the same P20/five-challenge caps.
All four receive distinct, non-exclusive solve strategies and same-chat changed continuations until
candidate, cumulative deadline, or interruption. Dynamic local-only passes still hand off early to
the one-instance queue.

Submission policy now separates candidate source qualification from method review. On a challenge
whose Board metadata exposes no attempt limit, each distinct source-qualified, non-model-supplied
candidate is durably reserved and submitted immediately through the fifth wrong response. The next
candidate requires existing independent verification. Explicit Board limits require verification
from the first candidate; pending/unread effects still fence all repeats; a current-run `correct`
still cancels siblings and closes the engagement. Verification remains available to improve or
confirm derivations, but no longer delays a free early Board oracle.

### Clean one-hour rerun and evidence-earned timeout Recovery

The replacement exact-image run from merged `b13cef5` completed its full hour with exit 0, started
all 15 engagements, terminalized all 94 attempts and 102 jobs, added one HTTP-200 `correct` on
Combination, and left zero pending effects, owned instances, live processes, or workspace residue.
It recorded 132 same-chat continuations, 2,681 committed tool observations with zero omission, 94
typed-memory projections, and 28 nonempty Recovery projections. Independent Daybreak/xhigh audit
found DB, evidence, model, Board, instance, and cleanup state clean. The raw external CPU/RSS/PID
series was not durably retained, so its observed aggregates are not promoted to independently
verified evidence. Full sanitized facts are in
[`issue-19-one-hour-rerun-evidence-2026-09-17.md`](issue-19-one-hour-rerun-evidence-2026-09-17.md).

The run exposed one narrow performance defect: all five timeout decisions were contained despite
committed evidence and unused successor budget. Three of those decisions ended the only three
Board-unsolved targets:
Telltale Beacon and Zip after one standard wave, and Parcelport after local plus one shared-instance
wave. The selected repair preserves safe candidate-free timeout checkpoints and admits exactly one
materially changed Recovery when committed observations and safety/deadline gates allow it.
Zero-evidence, unsafe, Verifier, duplicate, exhausted, and repeated Recovery timeouts remain
contained. Initial waves stay 2 Daybreak + 2 Luna; the single hard-timeout Recovery uses 3
Daybreak/xhigh + 1 Luna/max based on measured conversion, with no peer-count increase. Dynamic work
keeps the same one-instance lease across that successor and cleans once.

### Two-hour diagnostic scheduler design

The owner authorized a two-hour diagnostic before the final 5.5-hour acceptance and identified
three currently Board-unsolved targets: Telltale Beacon (15), Zip (94), and Parcelport (42). The
diagnostic must still cover the full catalogue, enable submissions and instances, and use the same
competition behavior except its outer deadline. `RAPIDO_FOCUS_CHALLENGE_IDS=15,94,42` supplies an
ordered prefix without narrowing coverage.

Controlled comparisons selected four small changes:

1. **Derived instance-ready heap over a new lease table.** The durable queued control wave and its
   `instance_enabled_follow_on` route already identify parked work. A new table duplicated that
   truth and added crash states. The selected broker parks the wave outside the five productive
   challenge slots, reconstructs it from the journal, and wakes exactly one waiter with priority.
   The live phase still consumes one of five slots. DELETE must prove absence before the next POST.
2. **Deterministic difficulty prior over learned scoring.** Learned expected-value scoring lacked
   duration and reliable practice crowd data. The selected order is explicit focus, then existing
   Board-unsolved/category/value order. The 800-second baseline remains. Explicit focus gets the
   available grant; other unsolved work scales from 800 to 1,800 seconds by Board value.
   Board-solved coverage stays 800 seconds. A full live admission needs 600 seconds. One productive
   timeout Recovery recomputes an automatic grant up to 1,800 seconds from remaining wall time,
   unresolved Board work, and five-way capacity. An explicitly configured larger baseline is
   preserved. Observed work, rather than guessed category, identifies later difficulty.
3. **Same-run idle watch over a second run.** A second run would reset the deadline and corrupt
   run-local accounting. The selected watcher retains the original run, polls IDs each minute,
   fully requalifies metadata and bounded attachment bytes every 15 minutes, atomically appends new
   challenges, and admits changed material as a new workspace generation. Earlier-generation facts,
   candidates, verification, routes, and Board outcomes remain private durable audit history but are
   excluded from new-generation memory and authority.
4. **Read-only CLI snapshot over a monitoring daemon.** `rapido monitor` reads query-only SQLite
   counters plus the solver container's cgroup-v2 files. `--follow --record-jsonl` appends sanitized
   0600 JSONL every ten seconds. It accesses no Board or model service, auth, model prose, candidate
   value, Docker socket, or process tree.

The prior queue held an entire engagement coroutine in each worker, so one live dynamic challenge
plus four lease waiters could consume all five slots. A six-dynamic regression now proves all six
finish local analysis while only one instance exists, then verifies six one-for-one POST/DELETE
cycles whose durable wake order matches actual lease order, plus six park/wake pairs. Focus/budget,
same-URL content refresh, idle append, query-only monitoring, private JSONL, and 12-core cgroup
parsing have focused coverage. The final local gate is green: Ruff and diff checks pass, and pytest
reports 857 passed and
one skipped in 107.13 seconds. Independent review found no unresolved P0-P3 defect after clarifying
that 1,800 seconds caps automatic grants, not an explicitly configured longer baseline. Exact-image
validation and the two-hour live result remain pending.

The Board client exposes no strong attachment validator, so exact same-URL change detection uses
bounded GETs during the 900-second idle full refresh. At the default 128 MiB per attachment and 15
challenges, the conservative ceiling is about 1.9 GiB per refresh, or about 41 GiB across 5.5 hours.
This cost occurs only after the solve queue drains; probe bytes are deleted immediately, and the
actual lane download is hashed again before use. Conditional GET with a proven strong ETag is a
future optimization, not a reason to weaken current-generation isolation.

The current host has 14 CPUs. The dedicated `colima-rapido` VM changed from 8 to 12 CPUs while
retaining 24 GiB RAM and expanding from 500 to 700 GiB disk; `docker info` reports 12 CPUs and
25,146,642,432 bytes. This leaves two host CPUs and provides headroom for offline crypto or
tool-heavy challenges. It does not raise P20 model admission by itself; the diagnostic sampler must
show whether local CPU becomes the next bottleneck. After the prior one-hour evidence merged, its
exact stopped container and state volume were deleted from `colima-rapido`; both are absent, while
the legacy `rapido-auth-v4` volume and current private host-bound credentials remain present.

### Post-diagnostic audit and selected execution repair

The owner supplied a private GPT-6 Pro audit archive after the two-hour diagnostic. It was extracted
into a private temporary directory, treated as untrusted data, and deleted after read-only triage;
its scripts were never executed and the archive is not a repository artifact. Cross-checking its
claims against the durable database and source confirmed a continuation concentration (737 total,
609 on one challenge), extensive failed observations, cancellation-evidence loss, five serialized
leases, and settled-candidate/monitor projection defects. Aggregate findings informed fixes; raw
candidate, target, alias, event, and timeline data remain private.

Controlled review selected these bounded repairs over a new agent framework:

1. **Persistent challenge residency.** Production watching runs treat an episode as a fair work
   quantum, not a give-up cap. Unresolved work re-enters FIFO with one of 32 semantically distinct
   perspective/tool-method combinations until the
   original deadline. A challenge closes only on current-run `correct`, non-validating
   `already_solved`, unsupported type, or deadline interruption. New Board challenge IDs are
   qualified and appended during active work without interrupting current lanes; the idle watcher
   retains full same-URL material refresh. The no-progress guard is 900 seconds, intentionally above
   the normal 800-second pass so it cannot cut off a thinking Daybreak lead; absolute attempt and run
   deadlines remain authoritative.
2. **Productive instance arbitration.** Dynamic challenges analyze locally first. A ready dynamic
   blocked behind the occupied lease yields its challenge residency when non-instance work is queued,
   preventing waiters from starving static analysis. With free lease capacity, or when only dynamic
   work remains, ready challenges stay resident and use the target slot.
   FIFO tickets survive deferral; one shared target wave releases and proves deletion before the
   next lease. Admission is rechecked before grant and after instance creation, so a waiter cannot
   cross the 600-second live-work floor unnoticed.
3. **Selective same-run context.** Typed memory projects up to 24 KiB of newest useful per-peer
   methods, host facts, failures, and next steps without cross-lane prose or candidate material.
   Safe files under `rapido-analysis` may carry into a changed non-Verifier episode for identical
   material, bounded to 64 files/16 MiB. Endpoint-, flag-, credential-, link-, and hardlink-like
   content is rejected; Verifiers receive neither memory nor carried scripts.
4. **Useful shell and target scripting.** The normal confined shell remains available for writing
   and running analysis code. `run_target_script` adds saved Python scripts whose worker has no
   direct network; an AF_UNIX broker exposes only the assigned target through bounded HTTP/TCP
   operations, multiple sessions/connections, exact cleanup, and candidate-safe target
   observations. Per-turn and target call ceilings rise from 100/80 to 512; they remain hard
   resource guards rather than attempt-longevity controls.
5. **Immediate effect and private retention.** Distinct source-qualified candidates still submit
   immediately through the fifth wrong on unlimited challenges. A settled same-context identity is
   never resubmitted; each intent snapshots its material digest, so historical effects cannot become
   a fresh run-local solve or suppress changed-material candidates. `correct` and `already_solved` cancel siblings and vacate the challenge slot
   immediately; rejected identities no longer remain candidate-like.
6. **Exact recovery and observability.** Attempt tool counts are monotonic across checkpoints.
   Streamed host observations survive timeout/cancellation without relying on exception attributes;
   incomplete projections retain exact call counts and an explicit evidence gap. Failed tool facts
   add bounded error code, retryability, and duration. Monitor v2 distinguishes running,
   reserved, completed-waiting, queued, and instance-wait states and consumes deferral/expiry
   transitions instead of leaving phantom waiters.

Post-implementation focused verification covers persistent requeue past the configured episode cap,
active Board append, static work escaping instance-wait starvation, FIFO lease lifecycle, late
instance admission, same-material carry and unsafe-content rejection, Verifier isolation, streamed
cancellation evidence, settled-candidate run/material scope, immediate-correct pending-count
cleanup, and target-script transport/provenance. Independent Daybreak/xhigh review found the
watcher, ticket, monitor, admission, and historical-effect defects above; all selected findings were
reproduced before correction. Full suite, final independent two-axis review, CI, exact-image
pressure/preflight, and the fresh two-hour Board diagnostic remain gates.

The two-hour diagnostic protocol remains all 15 challenges with focus order 15/94/42, five challenge
residencies, four peers per challenge, submissions/instances/watch enabled, a fresh empty state,
and the exact merged image. It is diagnostic only. The unchanged issue-19 completion gate still
requires later owner authorization and a fresh unattended 19,800-second acceptance run.

## Model/effort ledger

| Work | Effective selection | Result |
| --- | --- | --- |
| Lead orchestration | `gpt-6-astra` / `xhigh`, then direct `gpt-daybreak-blue-latest` / `xhigh` after first Astra failure | Astra interface lane hit `cyber_policy`; switch recorded before accepting further architecture work |
| Primary-source agent-system research | `gpt-6-astra` / `xhigh` | complete; configured selection, no worker-side runtime attestation |
| Architecture/red-baseline audit | `gpt-daybreak-blue-latest` / `xhigh` | complete; configured selection, no worker-side runtime attestation |
| Read-only predecessor-principle audit | `gpt-5.6-luna` / `xhigh` | complete; read-only/non-live |
| Three-way Interface comparison | `gpt-daybreak-blue-latest` / `xhigh` | complete after interrupted Astra arms; closed-core hybrid selected |
| Initial red replay fixture | `gpt-5.6-luna` / `xhigh` | rejected by independent review; hard-coded conclusions were not accepted |
| Red replay review | `gpt-daybreak-blue-latest` / `xhigh` | complete; required production-seam rewrite |
| Red replay production-seam rewrite and fixes | `gpt-daybreak-blue-latest` / `xhigh` | complete; evidence-only replay after removing a rejected self-asserted prospective gate |
| Red replay re-reviews | `gpt-daybreak-blue-latest` / `xhigh` | complete; successive reviews rejected and drove fixes for prospective-gate defects before PR |
| Red replay clean release review | `gpt-daybreak-blue-latest` / `xhigh` | complete; rejected a speculative green gate and triggered an evidence-only red-baseline correction |
| Evidence-only red replay release review | `gpt-daybreak-blue-latest` / `xhigh` | complete; release accepted with no P0-P3 findings, no fallback |
| Python 3.12 CI signal-fixture investigation | `gpt-5.6-luna` / `xhigh` | complete; confirmed inherited `SIGXCPU=SIG_IGN`, test-only reset selected, no fallback |
| Core public-seam/test design | `gpt-5.6-luna` / `xhigh` | complete; narrow non-live tracer sequence, no fallback |
| Core state/recovery design | `gpt-daybreak-blue-latest` / `xhigh` | complete; durable journal and at-most-once crash constraints, no fallback |
| Core routing/vault design | `gpt-daybreak-blue-latest` / `xhigh` | complete; failure fingerprints and private-retention boundaries, no fallback |
| Core journal independent review | `gpt-daybreak-blue-latest` / `xhigh` | complete; five P1 defects and one P2 overclaim found, all addressed test-first; re-review pending, no fallback |
| Core journal fix re-review | `gpt-daybreak-blue-latest` / `xhigh` | complete; one P1 terminal-overwrite crash window found and fixed test-first; clean re-review pending, no fallback |
| Core journal clean release review | `gpt-daybreak-blue-latest` / `xhigh` | complete; no P0-P3 findings, 81 focused tests clean, no fallback |
| Adaptive-router exploratory comparison | `gpt-daybreak-blue-latest` / `xhigh` | complete but unaccepted: no durable source/config/result artifact; harness pending, no fallback |
| Candidate-vault exploratory comparison | `gpt-daybreak-blue-latest` / `xhigh` | original numeric report unaccepted; superseded by the durable storage harness below, no fallback |
| Adaptive-router independent review | `gpt-daybreak-blue-latest` / `xhigh` | complete; eight P1 and three P2 defects found and repaired test-first; clean re-review pending, no fallback |
| Adaptive-router fix re-review | `gpt-daybreak-blue-latest` / `xhigh` | complete; two P1 and one P2 found, plus one false-positive fixture rejected; all fixed test-first, no fallback |
| Adaptive-router clean release review | `gpt-daybreak-blue-latest` / `xhigh` | complete; no P0-P3 findings, corrected escalation integration verified, no fallback |
| Candidate-vault comparison harness | `gpt-daybreak-blue-latest` / `xhigh` | complete; durable effect-free three-adapter storage subcomparison, full E2 behavior gate still pending, no fallback |
| Candidate-vault comparison review | `gpt-daybreak-blue-latest` / `xhigh` | rejected; raw gate, E2/E3 identity, pre-registration, provenance, and ledger defects found; fixes applied, re-review pending, no fallback |
| Candidate-vault comparison fix re-review | `gpt-daybreak-blue-latest` / `xhigh` | rejected; volatile crash stages were collapsed and rollback acknowledgements ungated; fixes applied, clean re-review pending, no fallback |
| Candidate-vault comparison clean review | `gpt-daybreak-blue-latest` / `xhigh` | complete; no P0-P3 findings, focused and full dual-version suites clean, no fallback |
| Private candidate-flow implementation and tests | `gpt-daybreak-blue-latest` / `xhigh` | complete locally; transactional private retention, fresh-context verification, adversarial and producer/Verifier real-crash tests, no fallback |
| Initial E2 candidate-flow behavior comparison | `gpt-daybreak-blue-latest` / `xhigh` | rejected; unequal budgets, SQL-vs-production admission, answer oracle, hard-coded selection, and incomplete source identity; artifact removed, no fallback |
| Candidate-flow independent review | `gpt-daybreak-blue-latest` / `xhigh` | rejected with five P1 and two P2 findings: incomplete host evidence, schedule-dependent verification, public digest leakage, uncontrolled comparison, non-source reobservation, incomplete provenance, and crash overclaim; no fallback |
| Candidate-flow fixes and corrected E2 comparison | `gpt-daybreak-blue-latest` / `xhigh` | complete locally; all findings covered test-first; 240 external-effect-free raw observations select private verification; clean re-review pending, no fallback |
| Candidate-flow clean release re-review | `gpt-daybreak-blue-latest` / `xhigh` | complete; v2 replay/source hashes and reversed-order fencing verified, no P0-P3 findings, no fallback |
| E3 routing protocol architecture | `gpt-daybreak-blue-latest` / `xhigh` | complete; four equal-budget arms, common authority boundary, raw-derived selection, and tamper gates frozen before measurement, no fallback |
| E3 narrow test-design lane | requested `gpt-5.6-luna` / `xhigh` | rejected; worker could not attest the required model, output is not model-valid evidence and was not accepted, no fallback |
| Initial E3 protocol independent review | `gpt-daybreak-blue-latest` / `xhigh` | held release: unfrozen fixture/policy/route values, aggregate circular evidence, FIFO gate contradiction, and declarative-only safety tests; all findings addressed before measurement, re-review pending, no fallback |
| E3 protocol second independent review | `gpt-daybreak-blue-latest` / `xhigh` | held release: FIFO was definitionally unable to convert, gate-negative fixtures were not isolated, comparator recipe was incomplete, and result-source provenance was missing; all findings addressed before measurement, clean re-review pending, no fallback |
| E3 protocol clean release re-review | `gpt-daybreak-blue-latest` / `xhigh` | complete; all frozen digests, comparator/gate semantics, E1/E6 locks, provenance contract, and protocol/brief SHA verified with no P0-P3 findings, no fallback |
| E3 implementation design | `gpt-daybreak-blue-latest` / `xhigh` | complete; comparison-only typed facts/policies and SQLite decision context selected without changing live route behavior; identified operation-unit registration gap before measurement, no fallback |
| E3 operation-count addendum review | `gpt-daybreak-blue-latest` / `xhigh` | complete after successive holds fixed config-byte, invocation, accounting, replay, and parent-schema ambiguities; final review found no P0-P3 findings, no fallback |
| E3 policy/state/harness implementation | `gpt-daybreak-blue-latest` / `xhigh` | complete locally; 30 E3 tests cover 2,160 rows, raw selection, native/thread/process fences, atomic crash recovery, and replay tamper rejection; no measurement before clean merge, no fallback |
| E3 implementation independent review | `gpt-daybreak-blue-latest` / `xhigh` | complete after holds for fact-link replay, raw-row/crash evidence, and native/thread/process monitor bypasses; final review found no P0-P3 blockers, no fallback |
| E3 CI memory-lifecycle fix review | `gpt-daybreak-blue-latest` / `xhigh` | complete; cached socket/process aliases blocked, global/profile restoration proven, and 8-process A/B showed old global hook worsened a separate pre-existing heap-threshold flake from 3/8 to 7/8 failures; rerun CI green, no fallback |
| E3 clean-source result review | `gpt-daybreak-blue-latest` / `xhigh` | complete; 2,160 rows, source/protocol hashes, operation totals, raw selector, replay, privacy, and zero-effect/leak gates independently verified; no blockers, no fallback |
| Initial M1 memory-core lane | requested `gpt-daybreak-blue-latest` / `xhigh`; worker reported `gpt-6-astra` / `xhigh` | rejected model-selection failure; draft treated as untrusted and sent through a fresh exact Daybreak implementation lane, no fallback |
| M1 memory-core implementation | `gpt-daybreak-blue-latest` / `xhigh` | complete locally; frozen fixture, privacy, private-context, dual-Python import, and static checks green, no fallback |
| M1 state/evidence independent review | `gpt-daybreak-blue-latest` / `xhigh` | release held for future-episode verification influence, raw manifest digest access, cross-lane prose access, and broad private rows; all corrected before integration, clean re-review pending, no fallback |
| M1 narrow test lane | requested `gpt-5.6-luna` / `xhigh` | rejected as model-valid delegated evidence because effective selection was unavailable; tests retained only after main-agent inspection and full-suite execution, no fallback |
| M1 implementation and harness release reviews | `gpt-daybreak-blue-latest` / `xhigh` | complete; privacy, source linkage, replay, fixture derivation, and exact selector clean before PR #31, no fallback |
| Repeated main CI signal/lifecycle review | `gpt-daybreak-blue-latest` / `xhigh` | complete; inherited blocked `SIGXCPU` root cause and no-overwrite M1 artifact lifecycle fixes verified before PR #32, no fallback |
| M1 clean-source result review | `gpt-daybreak-blue-latest` / `xhigh` | complete; source/protocol/addendum hashes, 112 rows, raw selector, privacy, replay, and zero-effect evidence independently recomputed with no P0-P3 findings, no fallback |
| Live engagement implementation review | `gpt-daybreak-blue-latest` / `xhigh` | complete after fixes for deadline cleanup propagation, deterministic instance lease order, one-create containment, and local-error episode preservation; final review found no P0-P3 findings, no fallback |
| Live engagement focused verification | `gpt-daybreak-blue-latest` / `xhigh` | 40/40 repeated dynamic lifecycle/order runs and 115 focused tests clean; exact-image calibration completed, no fallback |
| Corrected 1,800-second live calibration | Daybreak/xhigh Leads and Recovery; Luna max/xhigh Specialists | completed exact registered run; two new correct solves, P20, nonzero typed memory, no fallback |
| Corrected calibration lifecycle audit | `gpt-daybreak-blue-latest` / `xhigh` | clean: DB/FKs, jobs, effects, four instance lifecycles, two all-nine Board rounds, container, and workspace verified; no fallback |
| Corrected calibration result/contribution audit | `gpt-daybreak-blue-latest` / `xhigh` | clean: both corrects traced to Daybreak Recovery, immediate submit/cancel/cleanup/advance and typed-memory participation verified; no fallback |
| Persistent-primary diagnosis/design | `gpt-daybreak-blue-latest` / `xhigh` | one-thread cumulative-budget continuation selected; four-peer race and external deterministic coordinator retained; no fallback |
| Early-exit focused reproduction | `gpt-5.6-luna` / `xhigh` | non-live only; reproduced one-turn terminalization and fresh-thread Recovery; no fallback |
| Persistent-primary independent review | `gpt-daybreak-blue-latest` / `xhigh` | found provenance-subreason collapse and undeclared runtime callback; both fixed before release; no fallback |
| Same-run recovery interface comparison and review | three independent `gpt-daybreak-blue-latest` / `xhigh` lanes | selected existing-journal reuse; found and drove fixes for correct reconciliation, initial-before-retry order, atomic admission, stable catalogue order, exact binary config, bounded cleanup, scoped Board failures, restart-only allowance, and receipt mismatch; no fallback |
| Same-run recovery edge review | `gpt-daybreak-blue-latest` / `xhigh` | code paths clean; two P2 proof gaps closed with real qualified-candidate process loss and current-run receiptless-instance fencing tests; no fallback |
| Long-horizon solver research and `ctf-workspace` audit | `gpt-daybreak-blue-latest` / `xhigh` | complete; read-only evidence selects structural persistence and controlled short-prompt/tool-context tests, not framework import or broad fan-out |
| Candidate-proof repair review | `gpt-daybreak-blue-latest` / `xhigh` | clean; exact candidate/source/non-supplied manifest binding, legacy-row fencing, and quota-omission path independently verified; no fallback |
| Pressure harness implementation | `gpt-daybreak-blue-latest` / `xhigh` | complete locally; exact resource harness, no fallback |
| E4 deterministic pressure execution | no inference | complete from committed source and exact image; P4/P6/P8 green, P8 selected, P20 unchanged, 7.568 CPU cores/16.20 GB/188 PIDs peak, zero limit events, exact cleanup |
| Native shell independent review | requested `gpt-daybreak-blue-latest` / `xhigh` | complete; findings drove provenance, quota, durable evidence, execution, process isolation, semantic tool receipts, and Landlock fixes; final review found no P0-P3, but worker-side effective model metadata was unavailable |
| Failed one-hour diagnostic audits | `gpt-daybreak-blue-latest` / `xhigh` | complete; independently confirmed 133-tool lifecycle defect, 2+2 peer mix, persistent peers, immediate-through-five submissions, and exact sanitized result accounting; no fallback |
| Rerun-fix standards review | `gpt-daybreak-blue-latest` / `xhigh` | clean against `62909ac`; no code-quality, lifecycle, concurrency, SQLite, or maintainability findings; no fallback |
| Rerun-fix specification review | `gpt-daybreak-blue-latest` / `xhigh` | code clean; one stale README roster sentence corrected before release; merged-image diagnostic evidence remains pending, no fallback |
| Clean one-hour rerun lifecycle/result audit | `gpt-daybreak-blue-latest` / `xhigh` | clean DB/container/Board/evidence/model/memory/instance audit; all 15 started, one new correct, no fallback or residue; raw resource sampler not durable |
| Hard-target timeout diagnosis | `gpt-daybreak-blue-latest` / `xhigh` | Telltale Beacon, Zip, and Parcelport all had productive 800-second waves incorrectly contained; one bounded evidence-earned Recovery and 3+1 recovery roster selected, no fallback |
| Timeout-Recovery standards review | requested `gpt-daybreak-blue-latest` / `xhigh` | no P0-P2 defect; declined a P3 extraction that added abstraction without behavior; worker-side effective model metadata unavailable, so not accepted as model-attested evidence |
| Timeout-Recovery specification review | requested `gpt-daybreak-blue-latest` / `xhigh` | found an interleaved second-timeout dispatch defect; durable prior-Recovery fencing and regression coverage fixed it; re-review found no P0-P3 blocker; worker-side effective model metadata unavailable |
| Instance-ready queue design | requested `gpt-daybreak-blue-latest` / `xhigh` | derived durable park/wake queue selected over a duplicate lease table; worker-side effective model metadata unavailable |
| Priority/budget/watcher design | requested `gpt-daybreak-blue-latest` / `xhigh` | deterministic focus/value policy and meaningful 600-second floor selected over unsupported learned scoring; worker-side effective model metadata unavailable |
| Monitor design | requested `gpt-daybreak-blue-latest` / `xhigh` | query-only snapshot plus self-cgroup sampler selected over a daemon; worker-side effective model metadata unavailable |
| Private GPT-6 Pro archive triage | `gpt-daybreak-blue-latest` / `xhigh` | read-only untrusted extraction; validated scheduler/evidence/monitor findings only, archive excluded from Git |
| Selective analysis-carry tests | `gpt-5.6-luna` / `xhigh` | four focused tests cover safe carry, unsafe/link rejection, Verifier isolation, and latest-generation replacement |
| Post-diagnostic scheduler audit | `gpt-daybreak-blue-latest` / `xhigh` | watcher starvation, FIFO ticket loss, stale waiter projection, late admission, and historical-effect scope found and repaired locally |
| First exact two-hour diagnostic failure audits | two independent `gpt-daybreak-blue-latest` / `xhigh` lanes | writer/reader asymmetry for failed target-tool evidence confirmed against the immutable live database; no corruption, fallback, pending effect, or retained instance |
| External supervisor implementation and review | `gpt-daybreak-blue-latest` / `xhigh` | same-Run recovery, Board reconciliation, PID-1 descendant cleanup, pre-Run fail-closed behavior, and monitor projection merged in PR #55; clean independent review, no fallback |
| Board-literal provenance repair | `gpt-daybreak-blue-latest` / `xhigh` | one exact authenticated-description candidate under unlimited attempts; Board-origin success excluded from fresh verification and analysis coverage, no fallback |
| Rejected-candidate carry containment | `gpt-daybreak-blue-latest` / `xhigh` | current-context settled-wrong bytes and strict eight-hex encodings excluded privately from recursive files/paths, no fallback |
| Exact merged-image preflight | no inference | 15/15 authenticated catalogue, `writes=0`, temporary container/state removed |
| Replacement two-hour diagnostic live roster | `gpt-daybreak-blue-latest` / `xhigh`; `gpt-5.6-luna` / `max` and `xhigh` | 73 Daybreak and 71 Luna attempts on the registered mixed roster; no model fallback |
| Replacement diagnostic lifecycle/result audit | `gpt-daybreak-blue-latest` / `xhigh` | exact stopped state, database, candidates, instances, resources, and private exports audited; no new verified solve, no fallback |
| Main-CI failure diagnosis and test review | `gpt-daybreak-blue-latest` / `xhigh` | three real-time test races isolated; production change rejected, event-synchronized test-only repair reviewed independently; no fallback |
| Independent 15-candidate replay | three `gpt-daybreak-blue-latest` / `xhigh` lanes | eight verified, six unverified, one contradicted from fresh material and prior correct evidence; no fallback |
| `already_solved` lifecycle two-axis review | two `gpt-daybreak-blue-latest` / `xhigh` lanes | disclosure and mismatch-continuation findings fixed; clean P0-P3 spec review and clean P0-P2 standards re-review; no fallback |

The first Astra failure occurred during the minimal-Interface comparison: the provider returned a
cybersecurity policy stop before a design result. The two Astra comparisons already in flight were
interrupted without accepting their partial output. All three comparisons were immediately
re-dispatched as safe reliability-only work on exact Daybreak/xhigh. This is the contract's direct
switch, not provider fallback inside a solver run.

PR #38 had auto-closed #19 on 2026-09-17 despite its diagnostic-only protocol. The mismatch was
detected during this recovery slice and #19 was reopened before further delivery; final acceptance
and honest closeout remain pending.

PR #46 later auto-closed #19 again when its rerun fix merged. The independent one-hour audit caught
the mismatch; the main owner reopened #19 before the timeout-recovery delivery. It remains open.

### First exact two-hour diagnostic: failed evidence validation

The pre-registered run `b7ae2092c38a44559d660edbcce6462a` started from empty state on exact
image digest `sha256:008a035cb3325798b10c8839c9a696bde97abb247e3a9f7731d24284c213eec9`.
It exited 2 after 1,174 seconds, so it is failed diagnostic evidence and contributes no acceptance
solve. Before failure it began 9/15 challenges, closed three Board-solved challenges, submitted one
incorrect candidate, exercised prompt continuations, refilled solved slots, and requeued an
unsolved challenge instead of terminalizing it.

The fatal path was challenge 33 episode 1 after its local-analysis transition. Failed target tools
stored conservative error facts through `_recursive_facts`; object verification incorrectly applied
successful target metadata projection to the same facts. Three of 738 immutable evidence objects
therefore failed self-validation. SQLite integrity and foreign keys were clean. The exception
cancelled the wave, removed its sole instance, released its lease, sealed attempts, and finalized
the run `failed`. All four submission intents were settled; no local instance or pending effect
remained. The run is not eligible for same-run recovery because only process-lost `running` runs
resume. Its state must not be edited or reused.

The selected repair makes failed-object verification use the same conservative projection as its
writer. It accepts all 738 archived objects without weakening canonical digest, metadata,
candidate, or immutability checks. Regression coverage round-trips every target tool through
commit, reopen, and carry. A replacement diagnostic requires a new exact image, new protocol
registration, and newly empty state/workspace.

### Crash recovery and false-positive containment

PR #55 (`461a205`) adds the smallest complete external recovery boundary: one PID-1 supervisor
owns a disposable solver worker, one private state lock, and one sanitized sidecar record. An
unexpected worker exit can replace only the same durable `running` Run after 5/30/120-second
backoffs. The replacement keeps the original deadline and first reconciles Board state, unread
submissions, instance receipts, and controller jobs. Terminal, ambiguous, non-pristine, or
operator-stopped state stays quiescent instead of starting new work. Linux subreaper handling
signals the process group plus recursively discovered descendants and continuously reaps adopted
children while the worker lives; this prevents detached helpers or zombies from leaking across a
5.5-hour run.

Two narrow false-positive controls accompany recovery. Recursive carry now excludes any file or
relative path containing a settled wrong candidate from the current Run, challenge, and material
generation. Exact eight-hex candidates additionally exclude only their inner case variants and
four-byte endian encodings; arbitrary substrings are not mined. Separately, an unsolved
unlimited-attempt challenge may try one exact unique non-placeholder flag literal authored in a
freshly refreshed authenticated Board description. It submits once through the normal durable
reservation. Wrong retires the identity and analysis continues. Correct stops wasted work but is
recorded as Board-origin score evidence with `run_local_verified=false`; it does not start an
analysis job or satisfy fresh-derivation acceptance.

Verification was 951 passed / 4 skipped locally, 4/4 isolated Linux reaper regressions, green
Python 3.11/3.12 and amd64/arm64 CI, and a clean independent Daybreak/xhigh review with no P0-P3
findings. Exact merged image `rapido:issue19-recovery-461a205` has local image ID
`sha256:ff512ce2ddf761dde8d4d6ef9cf98aa9fd79d96be9be5231bb8c1f1c5698a090`. Its authenticated
preflight read all 15 challenges with `writes=0`; its temporary container and state volume were
deleted immediately afterward.

### Replacement two-hour diagnostic result

Run `82c928aff37148ea87e569f7c05c257d` used newly empty state on exact image
`sha256:675da3227355458b89552e8b967afffc821a14ef9b1b0418be32de7fc6f12835`. It ran unattended
from 00:11:49Z to 02:11:49Z on 2026-09-18 with submissions, instances, and Board watch enabled.
The five challenge slots admitted the registered focus order, refilled solved slots, and reached
all 15 challenges after 24 minutes 50 seconds. All work became quiescent after 78 minutes while
the watcher remained alive until the exact 7,200-second deadline.

The run completed 144 attempts and 5,035 model tool calls: 73 Daybreak/xhigh, 36 Luna/max, and 35
Luna/xhigh. It retained 25 source-proved proposals representing 16 distinct candidate values over
all 15 challenges. The Board returned 15 `already_solved` verdicts and one `incorrect` verdict;
there was no HTTP-200 `correct` verdict and no independent deterministic candidate verification.
Therefore this run contributes zero acceptance solves. In particular, a generic `already_solved`
response does not validate the submitted candidate. The candidates were exported privately for a
separate verification test; candidate bytes and raw logs remain outside Git.

Lifecycle checks found SQLite integrity `ok`, zero foreign-key violations, 144/144 sealed
attempts, all 16 submission intents settled, all nine owned instances `removed`, and no live
container process. Sampled resource peaks were 4.311 CPU cores, 979,427,328 bytes RSS,
1,112,322,048 bytes cgroup memory, and 140 PIDs, with no CPU, memory, or PID limit event. The
12-CPU, 24-GiB, 256-PID envelope was not the measured bottleneck; model conversion and candidate
verification were.

The exact private archive contains 478 files and excludes authentication. A structured candidate
export and requested 30-line challenge/flag projection are preserved as owner-only evidence; their
paths, values, and digests are not sanitized repository artifacts.

### Main-CI failure diagnosis

Two consecutive main pushes failed different Python jobs while the other Python version and both
container jobs passed. Run 35277255396 let a 0.25-second wall-clock deadline expire before the
second persistent episode on Python 3.12. Run 35296979507 let a 0.3-second deadline race the active
watch recovery on Python 3.11, so the run completed before the test's expected deadline. The
opposite-version passes and repeated local passes identify test timing races, not production
scheduler regressions.

The first PR #56 CI run then exposed the same defect in a third active-watch test: its 0.3-second
deadline expired after the simulated detail outage and before the material-retry cycle. The repair
changes tests only. The persistent-scheduler test now waits until episode three enters, then
deliberately cancels and checks the durable interrupted state. The first watch-recovery test holds
one solve across a coordinated outage, observes the recorded recovery, and proves one solve entry
with zero cancellations. The detail/material test waits until the newly admitted challenge starts,
then cancels and validates both outage cycles and recovery. Independent short timeouts bound test
failure without deciding test success. The three affected cases passed 20/20 repeated groups; Ruff
check/format and the updated 951-test local suite were green. PR #56 was squash-merged as
`6ab427cfe6b8848e576dbaa3700b8450e5acfed7`. Post-merge main run 35301678659 passed Python
3.11/3.12 and amd64/arm64 container jobs. No production file changed.

### Independent candidate replay and `already_solved` correction

Three independent Daybreak/xhigh lanes replayed all 15 selected candidates against a fresh,
read-only authenticated material download. Eight candidates were independently verified: challenge
IDs 7, 15, 17, 80, 90, 94, 106, and 109. Six remain unverified because their archived dynamic raw
response or full static derivation was insufficient: IDs 11, 19, 24, 33, 68, and 72. Challenge 42
was contradicted: its selected `already_solved` candidate differs from the candidate that earned an
HTTP-200 `correct` in run `acc972712a6148b19447c624e54803d7`. Conversely, challenge 15's current
selection exactly matches an earlier HTTP-200 `correct`. Candidate identities remain owner-only.
This controlled comparison proves that generic `already_solved` is neither uniformly right nor
uniformly wrong and cannot authorize closure by itself.

The corrected lifecycle keeps the immediate-submit policy and at-most-once effect fencing. A first
unlimited source-qualified candidate is still submitted immediately. If the Board returns
`already_solved`, the settled identity is retained privately, is not resubmitted, does not cancel
peers, and remains eligible for a fresh same-run Verifier. Only a verified identity may then close
the challenge without a new `correct`; a mismatch continues through changed Recovery work. The
owner-only corrected 30-line export replaces challenge 42 with its prior HTTP-200-correct value;
its digest remains private.

Local release validation is 953 passed / 4 skipped; focused match, mismatch, at-most-once, and
changed-route regressions pass. Ruff check/format and `git diff --check` are clean. Independent
Daybreak/xhigh spec re-review found no P0-P3 issue; standards re-review found no P0-P2 issue and
accepted two P3 centralization/type refactors as intentionally out of scope for this narrow fix.

## Open decisions

- PR #57 merged the evidence-driven `already_solved` correction with green CI. Preserve owner-only
  candidate exports; no candidate value belongs in Git.
- Complete the external-stop and post-run solver-audit repairs, independent review, merge, and one
  fresh 1,800-second diagnostic under the amended completion contract below.

### Owner amendment: completion gate moved out of this task

On 2026-09-18, after reviewing the two-hour diagnostic, the owner explicitly moved the unattended
19,800-second acceptance run to a different place. This is a post-observation amendment. It does
not mean the original gate passed, and this task must not claim a 5.5-hour result.

The amended completion contract for this task is:

1. Fix every confirmed P1/P2 finding from the last-run GPT-6 Pro audit without weakening candidate,
   target, credential, submission, instance, or cleanup controls.
2. Obtain independent Daybreak/xhigh review, resolve findings, pass repository CI, and squash-merge
   the focused repairs.
3. Pre-register and run one fresh 1,800-second unattended diagnostic from the final merged image,
   with empty state/workspace, all 15 challenges, submissions, managed instances, and Board watch.
4. Require clean durable termination, settled effects, removed instances, no process/workspace leak,
   no fallback, and private exports before exact run-state cleanup. The diagnostic tests the fixes;
   it is not a substitute for the relocated 19,800-second gate.
5. Merge sanitized evidence and close issue #19 honestly under this owner-amended task scope.

### Last-run audit remediation

The imported audit identified eight findings. PR #57 already resolves F03/F05's exact candidate
re-entry and prose-equality cases. The remaining implementation is split into two focused releases:

- F07/F08: an operator stop becomes durably terminal from active, scheduled, or blocked state;
  pending/unread effects remain unresolved; a parent-controlled exec gate closes the final launch
  race; the 190-second outer grace exceeds the 180-second worker drain and cleanup/persistence tail.
- F01: run reports separate Board outcomes, correct-candidate provenance, independent verification,
  and scheduler lifecycle. Outcome and provenance commit atomically. Verification is bound to the
  current material and, for dynamic work, the owned instance-generation receipt; unscoped legacy
  rows do not qualify. The historical two-hour run remains zero HTTP `correct` and zero same-run
  independent verification; later private replay stays separately labelled.
- F02: continuation progress is earned only by a novel successful host observation after removing
  timing-only fields. Paraphrased prose, failed calls, and duplicate observations cannot reset the
  bound; the no-progress watcher applies to 800-second attempts too.
- F04: repeated carry round trips canonicalize imported paths instead of nesting `carried/`;
  fresh files override imported same-path files; deterministic round-robin allocation prevents a
  low-numbered lane from consuming the 64-file cap; narrow retries preserve untouched lanes while
  an empty current lane retires stale same-lane carry; candidate-free telemetry accounts for drops.
- F06: tool and solver contract failures retain only a closed, bounded diagnosis—stage, field,
  constraint, actual kind/size, retryability, or parser category. Raw rejected values and model text
  remain excluded.

PR #58 passed independent Daybreak/xhigh review and four CI jobs, then squash-merged as `cd812bd`.
Independent Daybreak/xhigh review of PR #59 then found seven reproducible boundary defects. The
repair binds dynamic verification to the current instance receipt and archives it on generation
rotation; persists submission provenance before the Board POST; records reconciled outcomes with
unknown HTTP status; serializes additive migrations; resolves file/directory carry collisions;
types malformed solver, target, and media inputs; and suppresses raw exception text at the model
tool boundary. Direct HTTP-200 and reconciled-correct counts remain separate. The unrelated
Python-3.12 PR failure was a sub-second test clock race; its window is widened while preserving the
same production assertion.

The next exact-head tool/carry review found three adjacent cases: untrusted tool error codes could
still escape the closed boundary; prefix-conflict selection was quadratic before the 64-file cap;
and a failed staging rename could leave a dot-prefixed temporary in retained carry. The follow-up
projects error codes onto a fixed registry, resolves path prefixes in linear work over path depth,
and unlinks failed staging temporaries before continuing.

Local validation after these review fixes is 992 passed / 4 platform skips, plus 426 focused passes
and 3 skips. Ruff check/format and diff checks are clean. Exact-head independent re-review, PR CI,
final merged-image registration, and the 30-minute diagnostic remain pending.
