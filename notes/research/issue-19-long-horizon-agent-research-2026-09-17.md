# Issue #19 long-horizon agent research — 2026-09-17

Status: research only. No Board, model, container, credential, submission, or instance effect.
External sources were read on 2026-09-17. The predecessor repository was read-only; no code, answer,
artifact, run state, or scale is reused.

## Decision

Keep the merged persistent-Daybreak design as the leading hypothesis and measure it before adding
agents, retries, deadlines, or framework machinery. The smallest credible next change is an
outcome-first initial prompt with explicit persistence, tool use, success, and terminal-blocker
rules. An early model response is a checkpoint inside the same native conversation; a process-loss
requeue instead starts fresh inference from bounded typed run-local state. Tool capability and
dynamic/static order need separate controlled tests.

## Evidence and Rapido hypotheses

**Early exits and the first prompt.** The corrected calibration recorded fourteen non-correct
Daybreak turns ending `unsolved` or `unsupported` after median 65.233 seconds despite an 800-second
cap; eight ended before 120 seconds. The cap was only a maximum, so unused time and conversation
were discarded. Two later Daybreak Recovery lanes produced the run's two `correct` verdicts
([calibration evidence](issue-19-corrected-calibration-evidence-2026-09-17.md#diagnosed-conversion-loss)).
OpenAI's model guidance says an explicit persistence reminder prevents premature yielding and a
tool-use reminder discourages guessing; that reported benefit is GPT-4.1-specific, not evidence for
Daybreak ([OpenAI model guidance](https://developers.openai.com/api/docs/guides/latest-model?model=gpt-4.1)).
Current OpenAI guidance favors a clear outcome, success criteria, constraints, available context,
and stopping conditions over prescribed steps
([OpenAI outcome-first guidance](https://developers.openai.com/api/docs/guides/latest-model?model=gpt-5.5)).
Anthropic likewise found that a high-level prompt plus compaction was insufficient for multi-session
work, while explicit feature state and incremental goals helped
([Anthropic long-running harness](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents)).

Hypothesis H1: the 65-second cluster was primarily a stopping-contract defect, not a resource or
deadline defect. “Simple first prompt” should mean a short outcome contract—obtain one source-proven
correct result; use real tools; `unsolved` is a checkpoint; stop only on success, budget, or a proved
terminal blocker—not a vague one-line request or a long tactic script. The merged prompt now states
this, but native conversion is unmeasured (`rapido/solver.py:602-647`). Anthropic's reported
“context anxiety” is only an alternative to instrument: it concerns perceived context limits and
does not diagnose a 65-second turn
([Anthropic harness design](https://www.anthropic.com/engineering/harness-design-long-running-apps)).

**Same-chat continuation and compaction.** Codex includes prior messages and tool calls when a new
message continues an existing thread, and compacts long histories after a threshold
([Codex agent loop](https://openai.com/index/unrolling-the-codex-agent-loop/)); the Agents API also
defines a session as preserved configuration, conversation, and saved work that later messages can
continue ([OpenAI sessions](https://developers.openai.com/api/docs/guides/agents-api/sessions)).
Rapido now reuses one app-server thread, accumulates its tool evidence, and recomputes each turn's
timeout from one cumulative deadline (`rapido/codex_app.py:1908-2005`). Gap-specific, candidate-free
follow-ups cover `unsolved`, `unsupported`, malformed output, and four provenance failures
(`rapido/solver.py:52-82,672-700`; `rapido/orchestrator.py:1489-1604`).

Hypothesis H2: same-chat continuation will reduce repeated orientation and turn early final answers
into useful checkpoints. It must not reset time, evidence, repetition, or tool history. Compaction is
context management, not durable effect or provenance truth; record token/compaction events before
attributing any improvement to it.

**Requeue memory and crash continuation.** OpenHands persists conversation history, configuration,
tool outputs, workspace, and execution state under one conversation ID, then resumes it by ID
([OpenHands persistence](https://docs.openhands.dev/sdk/guides/convo-persistence)). Anthropic's
coding harness used progress artifacts and version history so fresh sessions did not rediscover
prior state ([Anthropic long-running harness](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents)).
These are operational contracts, not proof that raw history is safe here. The read-only predecessor
instead distinguishes persistent run authority from model-readable work, carries only selected
artifacts/facts into a fresh generation, and treats an early turn end as continuation inside the
same attempt (`/Volumes/Working/001 Projects/incypher-ctf/CONTEXT.md:340-375,491-553`). Its measured
principle is stronger than “resume everything”: turn boundaries preserve stall state, while process
loss closes half-observed work and opens a changed successor from bounded carry
(`/Volumes/Working/001 Projects/incypher-ctf/docs/adr/0035-confirmed-progress-buys-a-bounded-stall-epoch.md:27-82`;
`/Volumes/Working/001 Projects/incypher-ctf/docs/adr/0043-one-sequencer-owns-a-measured-rolling-working-set.md:144-151`).

Hypothesis H3: after process loss, a fresh Daybreak thread should receive only the committed
candidate-free checkpoint, sanitized host observations, typed tactic/failure records, and selected
content-addressed artifacts. Native transcript recovery is unnecessary and would weaken the current
private-candidate boundary. The merged same-run journal/requeue design follows this split; it still
needs a native conversion comparison.

**Retries are failure-specific.** SWE-agent separately bounds re-queries after formatting, blocked
action, or shell-syntax errors and persists trajectories across reviewed retry attempts; this is
implementation evidence, not a portable solve-rate result
([SWE-agent source](https://github.com/SWE-agent/SWE-agent/blob/main/sweagent/agent/agents.py)).
For Rapido: an early reasoning result gets a changed same-thread continuation; a transient tool or
transport error may repeat only after an observed condition change or bounded backoff; process loss
gets a fresh-thread requeue from committed state. Every path retains the original cumulative budget,
source evidence, and a materially changed input/condition. Policy, authority, and unchanged failures
remain non-retryable.

**Tool bootstrap.** OpenAI recommends passing tools through the API tool field with clear names,
detailed descriptions, and parameter descriptions
([OpenAI tool guidance](https://developers.openai.com/api/docs/guides/latest-model?model=gpt-4.1)).
Rapido passes app-server `dynamicTools` at thread creation (`rapido/codex_app.py:1723-1750`). The
model-visible base registry is twelve bounded tools (`rapido/tools.py:1429-1518`); shared-instance
work adds five authority-bound target tools (`rapido/target.py:467-546`). There is no general shell.
The predecessor's relevant principle is that installed, visible, authorized, and semantically
proved are distinct states; every exposed capability needs a functional receipt, not an import or
`--version` check
(`/Volumes/Working/001 Projects/incypher-ctf/docs/adr/0047-one-immutable-image-exposes-only-proved-free-tool-components.md:291-319,373-382`).

Hypothesis H4: “missing tool” has two separable causes: the required capability is absent from the
sealed registry, or the prompt/model fails to discover a present capability. Prompt retries cannot
repair the first. Before inference, bind a machine-generated capability receipt to the attempt;
inside the prompt, name only the relevant available capability family and require an initial
workspace/target inventory. Do not add a shell until a representative fixture proves a missing
semantic capability and the authority boundary is reviewed.

**Parallel work and ordering.** OpenAI recommends parallel subagents for independent tasks with
separate contexts and explicit expected results, while dependent steps stay with the lead
([OpenAI multi-agent guidance](https://developers.openai.com/api/docs/guides/agents-api/multi-agent)).
Anthropic's compiler project found parallelism useful for distinct failures but ineffective when
all agents hit the same sequential kernel blocker and overwrote one another
([Anthropic compiler account](https://www.anthropic.com/engineering/building-c-compiler)). Rapido's
private lane workspaces and controller aggregation fit the isolation principle; the live P20 run
showed capacity was healthy, but its initial five were 0/5. This does not justify more fan-out.

Current ordering is Board-unsolved first, then a deterministic mixture of one dynamic and up to
`active_challenges - 1` standards, ordered within type by category/value/id
(`rapido/orchestrator.py:864-891`). The Board measurement fixes live dynamic concurrency at one;
local dynamic analysis can still overlap standards. No reviewed first-party source proves
dynamic-first or static-first. Hypothesis H5: the present mixed front is safer than either extreme,
but long dynamic local-to-live paths may need an earlier seed while fast static work prevents the
single lease from dominating coverage. Select only from Rapido replay/native evidence.

## Smallest controlled experiments

Hold exact model/effort, fixture set, image, tool registry, total wall/token budget, provenance gate,
and zero-submission boundary fixed unless named. Record turn duration, stop reason, token/compaction
state, first-tool latency, tool count, repeated action fingerprints, source-qualified conversion,
and cost.

1. **P1—initial prompt:** current merged prompt versus the same prompt with only the four-line
   outcome/persistence/tool/stopping block promoted to the front. Use fixed safe artifact and local
   target fixtures. Select only if early non-correct finals fall and source-qualified conversion
   rises without policy/provenance regression.
2. **P2—continuation:** same initial prompt and cumulative 800 seconds; compare one-turn
   terminalization as a descriptive baseline. Compare changed follow-up in the same native thread
   against the same changed follow-up in a fresh thread with matched remaining time; only those two
   arms isolate conversation continuity. Same-thread must reduce repeated orientation or improve
   conversion; otherwise keep the simpler arm.
3. **P3—process-loss carry:** force exit after a committed candidate-free checkpoint. Compare fresh
   requeue with no carry versus the bounded typed checkpoint/observation/artifact projection. Require
   exact deadline/run/order replay, useful earlier facts, no candidate/cross-scope leak, and better
   conversion or fewer duplicate tools.
4. **P4—tool bootstrap:** with one fixed sufficient registry, compare current implicit schemas
   against a machine-generated relevant-capability block plus required first inventory. Add a
   deterministic negative fixture whose required capability is absent; it must fail pre-inference
   as typed `capability_unavailable`, not spend a model retry. This distinguishes discovery from
   inventory gaps. A separate injected transient-tool case permits one repeat only after a changed
   availability fact/backoff and must retain the original budget.
5. **P5—order:** replay the same sanitized 15-challenge durations, lease holds, and terminal classes
   under mixed, dynamic-first, and static-first order. Under the explicit fixed-outcome assumption,
   replay can reject mechanically poor coverage/lease utilization and compare time to a *recorded*
   validation; it cannot estimate counterfactual conversion. Then compare current mixed order with
   the best eligible alternative on fixed safe native fixtures while keeping the Daybreak/Luna
   profile and total budget fixed. Ties keep current order.

These experiments test the observed failure without weakening source binding, private candidate
handling, exact model enforcement, serialized effects, or the original 19,800-second ceiling.
