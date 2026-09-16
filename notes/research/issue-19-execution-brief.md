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

Completion requires one pre-registered, fresh-state, exact-final-image, unattended
`gpt-daybreak-blue-latest`/`xhigh` run with a 19,800-second work-admission budget, autonomous
qualified submissions, and managed instances enabled. It must analyze all 15 catalogue entries,
submit every freshly derived qualified candidate including candidates for Board-solved entries,
receive at least one new HTTP-200 `correct` verdict, bring cumulative autonomous solves from three
to at least four, and prove that a new routing, context, collaboration, recovery, or verification
mechanism materially contributed. Generic `already_solved` is never candidate validation.

The gate also requires exact model/effort with no fallback; no manual candidate relay or operator
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
| E4 | 2, 4, 6, then 8 inference lanes and scaled local-analysis workers | CPU, RSS, PIDs, model quota/latency, queue wait, Board/instance pressure, conversion | Stop increasing at first measured non-host bottleneck or safety boundary; keep full-wave admission |
| E5 | Crash points before/after queue admission, evidence/vault commit, submission intent/response, instance create/delete | Replay order, lost/duplicated work/effects, cleanup, DB integrity, residue | One durable owner; no duplicate POST, lost closed work, stale lane, or leaked instance/workspace |
| E6 | Read-only current Board inactive-instance observations with exact request contract | HTTP status, validated body shape, endpoint/timestamp presence, repeated coherence | Mutation allowed only after documented inactive semantics are positively established |

Every experiment records exact source, fixture identity, model/effort when used, configuration,
elapsed time, and a sanitized result. Native calibration is not a submission probe. Live solver
runs always use Daybreak/xhigh; Luna is restricted to narrow non-live fixtures/tests.

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

The provisional implementation uses the smallest fail-closed shape: exactly eight failure kinds,
two dispositions (`dispatch` or `contain`), immutable model/effort/effect authority, and a unique
material route fingerprint. Policy, provenance, timeout, quota, and Board failures remain
contained. Only two database-derived disagreement subreasons—one retained source candidate needing
verification or multiple distinct retained source candidates—may dispatch the exact Verifier
route; all other disagreement remains contained. Tool and safely identified local-container
failures may dispatch one changed route; persistent failures cannot turn episode, timestamp, or
retry ordinal into a change. This is a tracer under test, not the final E3 selection.

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
| Controlled architecture selection | Three-Interface comparison plus E0-E3; closed-core hybrid recorded | in progress: Interface selected; router merged; corrected E2 storage and behavior comparisons select private single-SQLite verification with clean review, pending final-image replay; prospective four-arm E3 protocol frozen before measurement and clean review, CI and result pending |
| Adaptive failure routing; no unchanged retry | Replay fixtures and route-fingerprint assertions | in progress: exact eight-class tracer and no-unchanged dispatch implemented; validated gated routes pending |
| Lead/Specialist/Verifier/Recovery cooperation | Typed engagement/replay tests | in progress: deterministic Lead, Specialist, and fresh-context Verifier implemented; Recovery route exists; full four-role/recovery proof pending |
| Private candidate retention and verification | Vault isolation, deterministic admission, false-positive tests | in progress: transactional same-run vault, unique exact verification, producer/Verifier crash and privacy/false-positive tests, corrected 20-repetition E2 comparison, and clean review green; final-image replay pending |
| Replayable ordering, extensions, 15/15 coverage | Queue replay/crash tests and final-run evidence | in progress: initial job order durable/replayable; queue authority, extensions, and acceptance coverage pending |
| Productive bounded resource scaling | E4 measurements and selected profile | pending |
| Crash-safe 19,800-second recovery | E5 plus final-run/restart evidence | in progress: process-loss jobs durably closed on restart; same-run continuation pending |
| Board inactive semantics established | E6 independent evidence | pending |
| Exact final image/protocol registered before state creation | Issue comment and immutable digest/source | pending |
| Fresh unattended all-15 run; >=1 new `correct`; cumulative >=4 | Sanitized exact-run evidence | pending |
| New mechanism materially contributed | Source-bound route/verification trace, sanitized | pending |
| No steering/fallback/pending/indeterminate/leak/regression | Audit, review, CI, Board and cleanup checks | pending |
| Exact run state deleted after evidence merge; auth preserved | Targeted post-deletion inspection | pending |
| #19 closed honestly | GitHub closeout linked to merged evidence | pending |

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

The first Astra failure occurred during the minimal-Interface comparison: the provider returned a
cybersecurity policy stop before a design result. The two Astra comparisons already in flight were
interrupted without accepting their partial output. All three comparisons were immediately
re-dispatched as safe reliability-only work on exact Daybreak/xhigh. This is the contract's direct
switch, not provider fallback inside a solver run.

## Open decisions

- Exact policy-compatible context variant selected by E1.
- E2-selected single-SQLite vault and `fresh_source_reobservation_v1` recipe require independent
  review and final-image replay before acceptance.
- E1-approved policy route, exact per-route budgets, and router selected by a reproducible E3 comparison.
- Parallel lane/local-worker profile selected by E4.
- Current Board inactive-instance contract established by E6.
- Exact merged commit, final image digest, final challenge order, deadlines, and measurement sampler
  to pre-register before the acceptance state exists.
