# Issue 19 — agent systems: primary-source evidence

Research date and access date for every external source: **2026-09-16**. This is a bounded
research note on reliability, provenance, isolation, and benign evaluation; it does not select
a solver architecture or propose live offensive automation. No Board work or model calibration
was performed.

Configured research lane: `gpt-6-astra` / `xhigh`, confirmed by the parent orchestrator's spawn
record. This lane has no independent server receipt attesting effective execution; configuration
is not presented as runtime attestation. No fallback was requested.

## Starting evidence

[Issue #19](https://github.com/jerome-queck/incypher-rapido/issues/19), read at its
`2026-09-16T01:22:42Z` revision, leaves architecture open. The
[issue #11 report](issue-11-completion-evidence-2026-09-16.md) records 15 policy failures, ten
provenance rejections, and 1/15 current-run verification; it records no timeout, resource,
transport, or restart failure explaining the loss. Its later cumulative-three acceptance was
an explicit post-observation amendment. These observations support better failure attribution;
they do not establish a need for additional agents, longer deadlines, or greater concurrency.

## Source matrix

Evidence classes: **controlled** compares alternatives; **observational** reports a deployed or
experimental system; **contract** specifies behavior without measuring task-success benefit.
Live documentation has no immutable revision unless one is stated below.

| Source; publication/version | Evidence and architecture | Transfer and limits |
| --- | --- | --- |
| [Towards a Science of Scaling Agent Systems](https://arxiv.org/html/2512.08296v3), v3, 2026-04-08 | **Controlled:** 260 configurations; six benchmarks; single, independent, centralized, decentralized, hybrid; matched tools, prompts, compute. Relative effects range from +80.8% on decomposable financial reasoning to −70.0% on sequential planning. | Task structure governs benefit. Cross-validated R² is 0.373, or 0.413 with task-grounded capability; 87% architecture selection concerns held-out configurations, not arbitrary new domains. Do not reuse v2's 180 configurations/four benchmarks/R² 0.524 as current results. |
| [Anthropic Research](https://www.anthropic.com/engineering/multi-agent-research-system), 2025-06-13 | **Observational:** lead researcher delegates independent searches; specialists return compressed findings; a citation agent attributes the final report. Internal evaluation reports 90.2% improvement over single Opus 4. Typical multi-agent token use was about 15× chat usage. | Supports explicit assignments and artifact references for broad research. The improvement is not a published equal-budget causal estimate, and 15× compares against chat, not the single-agent research baseline. Its synchronized subagent batches also create waiting bottlenecks. |
| [Why Do Multi-Agent LLM Systems Fail?](https://arxiv.org/abs/2503.13657v3), v3, 2025-10-26 | **Observational:** 1,600+ annotated traces from seven frameworks; taxonomy derived from 150 expert-reviewed traces, κ=0.88; 14 failure modes across system design, inter-agent misalignment, and verification. | A useful diagnostic vocabulary. It does not establish that naming more roles resolves those failures; benchmark/model coverage differs from this repository. |
| [Harness design for long-running applications](https://www.anthropic.com/engineering/harness-design-long-running-apps), 2026-03-24 | **Observational:** planner, generator, evaluator; explicit per-sprint acceptance criteria; evaluator interacts with the application. Separate evaluation addresses observed self-grading leniency. | Distinguishes producing work from checking it. The evaluator remains fallible. Sonnet 4.5's context-reset workaround became unnecessary for Opus 4.5: harness assumptions need remeasurement after model changes. |
| [RouteLLM](https://arxiv.org/html/2406.18665v4), v4, 2025-02-23 | **Controlled:** learned strong/weak model routing evaluated on quality–cost curves; reported cost ratios depend on benchmark and retained quality. Training/evaluation similarity affects results. | Evidence for measured routing tradeoffs, not for retrying policy refusals or runtime recovery. Its single-turn preference setting does not validate a failure-aware multi-step router. This repository's fixed live model/no-fallback contract excludes directly adopting strong/weak routing. |
| [LangGraph state](https://docs.langchain.com/oss/python/langgraph/graph-api), live documentation | **Contract:** schemas define state, input/output projections, and reducers; internal channels can be absent from public output. Nodes can write channels beyond their input projection. | Typed state can distinguish records and merge rules. A `PrivateState` name or output filter does not prove authorization, isolation, redaction, or runtime validation of every transition. |
| [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence) and [subgraphs](https://docs.langchain.com/oss/python/langgraph/use-subgraphs), live documentation | **Contract:** checkpoints preserve graph steps; completed sibling writes can survive another node's failure. Per-invocation subgraphs start fresh while inheriting checkpoint support; per-thread state can persist across calls. | Same-run continuation and a new evaluation run need different identities and retention lifetimes. Checkpointing alone is not proof that external effects execute once or that a public trace excludes internal state. |
| [Managed Agents](https://www.anthropic.com/engineering/managed-agents), 2026-04-08 | **Observational:** separates durable session event log, model harness, and disposable sandbox; harness and sandbox can fail independently. Credentials remain outside generated-code execution. | Useful separation between durable evidence, model context, and executable workspace. This is a first-party production account, not a controlled comparison or reason to copy its distributed deployment scale. |
| [Temporal workflow definition](https://docs.temporal.io/workflow-definition) and [activity definition](https://docs.temporal.io/activity-definition), live documentation | **Contract:** replay must issue the same command sequence from recorded history. Nondeterministic calls belong outside replay. Completed activities are not repeated during replay, but an effect completed before its completion record can be retried. | Durable recovery requires stable ordering and idempotent effects. A checkpointer does not create an external service's idempotency guarantee; workflow code changes also need replay compatibility. |
| [Temporal error handling](https://docs.temporal.io/develop/python/best-practices/error-handling), live Python SDK documentation | **Contract:** application errors and retry policies can mark permanent failures non-retryable; authorization failures are an example. | Supports distinguishing transient infrastructure failure from invalid input, authorization, or policy stops. Automatic retries cannot repair every failure class. |
| [Temporal failure detection](https://docs.temporal.io/encyclopedia/detecting-activity-failures), live documentation | **Contract:** separates queue wait, per-attempt time, overall execution time, and heartbeat intervals. Heartbeats may carry progress; transport throttling means the newest local heartbeat may not survive a crash. | Liveness and useful progress differ. Heartbeat renewal does not remove the overall execution deadline or prove result correctness. This is not controlled evidence for progress-earned time extensions. |
| [Ray resources](https://docs.ray.io/en/latest/ray-core/scheduling/resources.html), documentation build 2.58.0 | **Contract:** CPU/memory requests control logical admission; they do not enforce physical usage or CPU isolation. Threaded libraries can exceed an assumed worker allocation. | Worker count is not a resource guarantee. Explicit admission and operating-system enforcement solve different problems. No Ray adoption or concurrency setting is established here. |
| [Linux cgroup v2](https://www.kernel.org/doc/html/v6.16/admin-guide/cgroup-v2.html), kernel documentation v6.16 | **Contract:** CPU bandwidth, memory limits/pressure, and PID controls are distinct. PID accounting includes kernel task IDs, hence threads; memory hard-limit pressure can invoke OOM killing. | Resource validation must observe all three dimensions and leave capacity for supervision/cleanup. CPU quota is not exclusive core allocation; memory hard limits are not admission estimates. |
| [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html), live guidance | **Contract/guidance:** record event classification and interaction identity; exclude or protect sensitive data; restrict log access and define disposal. | Supports useful reason-code telemetry without publishing private content. This repository is stricter: its issue contract also forbids publishing candidates and candidate digests. |

## Architecture implications to test, not prescriptions

**Failure-aware routing means choosing a permitted recovery action from a specific failure.**
Infrastructure timeouts, malformed results, evidence rejection, and policy stops should not be
pooled into a generic unsuccessful attempt. The transferable principle is typed failure handling
with bounded retries and explicit terminal classes. Policy or authorization rejection must remain
a stop, not trigger rephrasing or provider/model switching to evade it. The sources do not measure
which routing policy would improve this repository. See
[Temporal error classification](https://docs.temporal.io/develop/python/best-practices/error-handling)
and [RouteLLM's different evaluation setting](https://arxiv.org/html/2406.18665v4).

**Separate responsibility before deciding agent count.** For benign artifact tasks, Lead can own
assignment and aggregation, Specialist can produce a scoped artifact, Verifier can check its
acceptance contract, and Recovery can reconcile interrupted work. Recovery need not be another
LLM; deterministic reconciliation may fit it better. These are alternative responsibilities,
not evidence for four permanently running agents. Cross-agent conversation also does not
establish independent evidence: sharing a proposed answer before independent work can correlate
results. Preserve the repository's independence requirement while comparing alternatives.
This is an inference from [measured topology dependence](https://arxiv.org/html/2512.08296v3),
[external evaluation experience](https://www.anthropic.com/engineering/harness-design-long-running-apps),
and the local issue contract.

**Same-run memory should preserve epistemic status.** A compact summary, an unverified proposal,
an observation, and a verification result have different authority. A summary cannot promote an
assertion into verified evidence. Typed records and explicit merge behavior make that distinction
reviewable; persisted observations allow checking what a summary omitted. This is a design
inference from [typed state](https://docs.langchain.com/oss/python/langgraph/graph-api) and
[durable context separated from model context](https://www.anthropic.com/engineering/managed-agents).
Retaining private candidate material is a separate security decision: public telemetry should
carry allowed classifications, and any private retention must preserve access controls, same-run
scope, and required deletion. No source establishes that an output projection alone protects it.
See [OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) and the local
publication restrictions.

**Replayable ordering is stronger than “usually FIFO.”** Recorded outcomes, decisions, and
ordering must permit the same recovery decisions without consulting fresh model output or a new
wall clock. Concurrent completion can vary between original executions; replay should reproduce
the observed execution, not claim that independent fresh runs are identical. Stable tie-breaking
and versioned decision rules are possible local designs to evaluate. This follows
[Temporal's replay contract](https://docs.temporal.io/workflow-definition); it is not a claim
that a distributed task queue guarantees global FIFO.

**Evidence-earned extensions remain an open hypothesis.** None of the sources reviewed provides
a controlled comparison of progress-conditioned wall-time extension against fixed deadlines for
this repository. The prior run had no timeout loss. A benign experiment could distinguish
supervisor-validated milestones from repeated calls or self-reported confidence while retaining
an absolute deadline. [Temporal's separate timeout types](https://docs.temporal.io/encyclopedia/detecting-activity-failures)
support that distinction, not increasing the live solver budget.

**Crash safety has an effect boundary.** A crash after an external effect but before local
acknowledgment leaves an uncertain outcome. Replaying the local record cannot prove that the
effect did not happen. Recovery must use an established idempotency/reconciliation contract;
an unrecognized response remains indeterminate. This follows
[Temporal's activity failure window](https://docs.temporal.io/activity-definition) and preserves
issue #19's fail-closed lifecycle requirement.

## Benign experiments that discriminate alternatives

These are proposed local synthetic evaluations, not completed measurements or live-run plans.
Hold task set, model/effort, tools, total token budget, and machine envelope fixed when comparing
architectures; record latency and tool/token cost beside independently checked correctness.
This follows the controls in the
[scaling study](https://arxiv.org/html/2512.08296v3), without importing its effect sizes.

| Question | Local fixture/comparison | Evidence needed |
| --- | --- | --- |
| Does routing distinguish recoverable failures? | Benign parser/data-processing work; inject transient unavailability, malformed output, authorization denial, policy stop, cancellation. Compare generic retry with classified bounded handling. | Correct terminal class; bounded attempts; no retry of disallowed work; no additional authority. |
| Do separated roles improve checking? | Small document-extraction and arithmetic tasks with exact independent oracles; compare one worker, independent workers, and worker plus verifier under equal total budget. | False acceptance/rejection, correlated errors, complete-task correctness, elapsed time, coordination cost. |
| Does memory survive without laundering evidence? | Reset a benign task's context after partial progress; introduce stale, contradictory, wrong-run, and summary-only records. | Unverified records remain unverified; prohibited cross-run references rejected; public output contains no synthetic private canary. |
| Does restart preserve decisions and effect accounting? | Deterministic local fake service; interrupt before/after checkpoint, effect, and receipt boundaries; vary worker completion order. | Replay yields the recorded ordering and terminal state; no duplicate fake effect; unknown outcome stays unknown. |
| Do extensions reward useful progress? | Synthetic long calculations with oracle-checked milestones; compare fixed limit, liveness renewal, and validated-progress renewal within the same absolute ceiling. | Useful completion, wasted time, stale/replayed milestone rejection, cancellation latency. Evidence may favor keeping fixed limits. |
| Is capacity the limiting factor? | Harmless CPU, memory, and bounded-thread workloads with measured admission; observe the existing allowed envelope. | Tail latency, queue delay, peak memory/tasks, throttling/OOM/PID events, shutdown residue; no increase inferred merely from unused CPU. |

## Limits and checks

The first-party success reports demonstrate workable systems, not portable causal guarantees.
Research benchmark results do not validate policy-refusal reduction, candidate admission changes,
Board semantics, or longer live execution. No reviewed source validates a four-role architecture,
learned failure router, or particular concurrency level for this repository.

Sources were opened and current paper versions checked; an older scaling-paper revision was
explicitly superseded above. Documentation pages are mutable snapshots and require rechecking
before implementation. No dependencies, credentials, live data, Board effects, or runtime files
were changed. Only this research note was edited by this lane. Source/readback review completed;
`git diff --no-index --check /dev/null notes/research/issue-19-agent-systems-sources.md` produced
no whitespace diagnostics (exit 1 denotes the new-file difference). No behavior tests were run.
