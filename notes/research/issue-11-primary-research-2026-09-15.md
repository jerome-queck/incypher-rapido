# Issue 11 — primary research and minimal audit Interface

Date: 2026-09-15. Source revision: `2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9`.
Research worker: `/root/minimal_research`; selected model `gpt-6-astra`, effort `xhigh`.
Evidence: lead confirmed successful dispatch of that exact pair, without fallback. Worker-side
runtime self-introspection was unavailable; this records orchestration evidence, not self-report.

Scope: source inspection, public primary documentation, operational evidence, and a proposed
read-only audit Module. No runtime implementation, inference, authenticated Board access, target
interaction, or live evaluation occurred. Benchmark proposals use benign synthetic fixtures.

## Findings

| Area | Repository observation | Interpretation / unknown |
| --- | --- | --- |
| Scheduling | `run()` awaits each challenge before advancing; a semaphore admits lanes within that challenge. `attempts_per_challenge` creates separate artifact copies. [R1][R2] | The current topology is serial challenges with parallel lanes. Outer interval overlap does not establish backend inference overlap. |
| Context | Every `solve()` starts an ephemeral thread and one turn. Prompt fields contain challenge data, lane number, and artifact names. [R3][R4] | No successor-context workflow appears on this path. This observation does not establish that longer context would improve results. |
| Evidence | `SolverFinding` parses `evidence` and `next_steps`; `finish_attempt()` persists summary, candidate, confidence, and status. Wave events retain bounded tool names, success/provenance flags, and candidate hashes. [R4][R5][R6] | Durable state cannot reconstruct all returned findings or detailed tool observations. Model-written evidence strings are not independently verified facts. |
| Tool ceiling | Host `MAX_TURN_TOOL_CALLS` is **100**; one active tool request per turn is enforced. Issue #11 reports static lanes stopping at ten calls. [R7][R8][I11] | Ten-call stops are not evidence of this host ceiling firing. The limiting layer and reason remain unknown. |
| Tool scope | The registry has bounded file/archive/decoding/media/ELF/filesystem inspection; fixed output, scan, archive, command-time, and workspace-entry limits remain. [R9] | Breadth alone does not establish useful coverage. No challenge-specific tool expansion is recommended by this note. |
| Resource evidence | Prior final-image sweep: 14 paired waves, approximately 216 MiB peak memory, 59 PIDs, 1.73 CPUs; 8 CPUs/24 GiB enforced. [R10] | These observations do not identify whether remote inference, waiting, or host work dominates elapsed time. Low host utilization does not prove spare model capacity. |
| Measurement gaps | Native notification handling retains final messages and terminal results; token-usage/compaction events have no dedicated handler. [R11] | Token pressure, compaction frequency, and exact inference intervals cannot be recovered from current terminal summaries. |
| Fault locality | Thread setup failure fences the shared process. Workspace/thread registries clear at session close; completed turns remove turn maps. [R12] | A peer can share the failure domain. Retained registry growth is a source concern; no new leak measurement was made. |
| Evaluation | Current `run()` counts Board-solved records and skips them. Prior acceptance skipped one of 15; its full sweep disabled submission. Issue #11 instead requires fresh run-local scoring. [R1][R10][I11] | Earlier lifecycle acceptance does not establish the issue's final scoring criterion. |

Historical caution: the implementation audit labels its original findings superseded by subsequent
acceptance; its old missing-dynamic/media conclusions are not current source facts. [R13]

## Native Codex contracts

Current official documentation supports these primitives; availability in the pinned image remains
a separate compatibility question. Local read-only help reported `codex-cli 0.153.2`; the Dockerfile
pins `0.154.0`. Schema generation is version-specific. [R14][O1]

| Primitive | Supported contract | Limit of inference |
| --- | --- | --- |
| Connection and routing | Initialize once per connection; JSONL stdio; threads contain turns/items; progress carries thread/turn identity. [O1] | This is multiplexable protocol structure, not a numerical subscription concurrency or throughput guarantee. |
| Conversation lifecycle | `thread/start`, `thread/resume`, `thread/fork`; fresh, continued, or copied history. Dynamic tools are experimental and restored on resume. [O2] | Forked history is not independent evidence. Current documentation cannot certify pinned-image fields. |
| Turn control | `turn/start` supports model/effort/output-schema controls; `turn/steer` requires the active expected turn and cannot change those controls. Interruption terminates with `interrupted`. [O3][O4][O5] | An interrupt acknowledgement is not proof every external worker has exited. |
| Context observation | `thread/compact/start` returns immediately; `contextCompaction` items show progress. `thread/tokenUsage/updated` reports usage. [O6][O7] | Compaction does not certify preserved factual correctness; this note recommends no live continuation policy. |
| Retirement | Last-subscriber removal begins an inactivity grace period; current docs specify 30 minutes before unload. [O8] | Unsubscribe is not immediate memory reclamation. |
| Limits and identity | Model catalogue exposes supported effort options. Account limit read/update surfaces expose quota windows; model reroutes are observable events. [O7][O9] | Catalogue visibility and configured defaults are not proof of effective per-turn model identity or available parallel capacity. |

The documentation calls the app-server command/WebSocket transport experimental and unsupported
for production. Its managed-auth guide requires a single serialized owner of a credential copy and
limits that workflow to trusted private automation. [O1][O10]

## Board and runtime constraints

Public organizer guidance establishes isolated instances with expiry and per-instance results,
provided-target-only scope, team-key confidentiality, and an ADK release scheduled for 21 September.
It does not publish a numerical instance cap or atomic generation-delete contract. No authenticated
Board assumptions were rechecked here. [B1]

Repository acceptance reports quarantined receipt-less creates, receipt-matched cleanup, and a
remaining generation read/delete race. Those are prior repository observations, not a fresh
organizer guarantee. [R10] The local container contract sets one auth-owning app-server, 8 CPUs,
24 GiB, 256 PIDs, a roughly 500-GiB workspace ceiling, and a 180-second stop grace. [R15]
The native child receives an explicit environment without Board credentials. [R16]

Unknowns: simultaneous-instance cap, provider concurrency quota, organizer deployment/resource
contract, effective token/compaction behavior in `0.154.0`, and root cause of ten-call termination.
Prior sustainability evidence explicitly excludes a continuous 5.5-hour run and physical injection
of disk-full, host/daemon failure, auth expiry, and maximum-memory pressure. [R17]

## Measurable hypotheses and benchmark plan

Proposed operational measurements only; none were run in this lane. Keep the existing live runtime
unchanged while evaluating the read-only audit Interface against generated event histories.

| Hypothesis | Benign fixture / measurement | Predeclared evidence criterion |
| --- | --- | --- |
| Missing telemetry is distinguishable from zero usage. | Synthetic traces with absent token/resource/terminal events. | Every missing required metric is `unknown`; zero missing values silently become zero or pass. |
| Terminal summaries conceal unfinished ownership. | Replay normal completion, timeout, interruption, duplicate/out-of-order completion, and process exit without worker exit. | Every deliberately unresolved owner is reported; zero false clean reports. |
| A common audit representation prevents source-format drift. | Equivalent sanitized JSON export and closed SQLite snapshot; same policy. | Identical normalized assessment; source identity retained; byte-for-byte source unchanged. |
| Fault effects can be classified without raw transcripts. | Synthetic shared-process failure affecting two traces; include secret and candidate sentinels in excluded fields. | Both affected traces accounted for; zero sentinel disclosure; exact missing evidence listed. |
| Repeated audit work has bounded retained resources. | 96 cycles after three warmups, following the existing synthetic-harness scale. [R17] | Zero open descriptors/tasks left after each call; source and output byte counts recorded; memory slope reported, not extrapolated into a pass. |

For any later benign native compatibility check, freeze binary/image digest, fixture digest,
requested and observed model/effort, host limits, and protocol schema before comparison. Record
turn acknowledgement, first event, last event, terminal status, tool duration, cancellation drain,
RSS/PIDs/file descriptors, and available usage events. Missing observations must remain explicit.
These tests would establish operational correctness, not competition solve improvement.

## Alternative design: two-entry-point `RunAudit`

**Module:** a read-only assessor of completed, sanitized operational evidence. **Seam:** between an
immutable evidence snapshot and a reviewable assessment. The caller never handles native sessions,
queue claims, Board effects, candidate values, or cleanup operations through this Interface.

Illustrative types; proposal only:

```python
AuditSource = SanitizedExport | ClosedSqliteSnapshot
Gate = Literal["pass", "fail", "unknown"]

AuditPolicy(required_metrics, maximum_drain_seconds, maximum_input_bytes)
Assessment(source_digest, run_id, coverage, metrics, gates, missing_evidence)
Comparison(comparable, metric_deltas, gate_changes, exclusions)

assess(source: AuditSource, policy: AuditPolicy) -> Assessment
compare(baseline: Assessment, candidate: Assessment) -> Comparison
```

**Interface invariants:** immutable source; explicit source revision/digest/run identity; closed
snapshot only; allowlisted scalar/count fields; no raw transcript, summary, secret, or candidate
output. Missing data yields `unknown`; it never proves cleanup or success. Assessments are
deterministic for the same source and policy. Comparison requires compatible fixture/schema/unit
definitions and lists excluded metrics instead of merging incompatible histories.

**Ordering:** obtain the closed snapshot, call `assess`, then optionally `compare`. Callers retain
the returned result. No initialization, polling, retry, scheduler, or shutdown lifecycle is exposed.
**Errors:** `InvalidSource`, `UnsafePath`, `UnsupportedSchema`, `InputLimit`, and `SourceChanged`;
none returns a partial passing assessment. Runtime grows with bounded input size; no inference or
remote access occurs.

```python
baseline = assess(SanitizedExport("baseline.json"), policy)
candidate = assess(ClosedSqliteSnapshot("fixture.sqlite3"), policy)
comparison = compare(baseline, candidate)
```

**Hidden implementation:** source validation; schema normalization; deterministic event ordering;
terminal-state consistency checks; ownership accounting; unit normalization; missing-data tracking;
redaction; metric comparisons. It does not instantiate the current `StateStore`, whose constructor
opens writable state, adjusts modes, enables WAL, and creates tables. [R18]

**Dependencies / Adapter strategy:**

- **In-process:** normalization, event checks, metrics, and redaction; direct tests at this Interface.
- **Local-substitutable:** filesystem and SQLite; internal read-only SQLite Adapter and sanitized
  JSON Adapter, exercised using temporary local fixtures. Both justify a real internal Seam.
- **Remote but owned:** none needed; no speculative port.
- **True external:** Codex and Board are outside this Module. Their sanitized recorded events are
  input data; no live Adapter or mocked promise of backend behavior.

**Depth / Leverage:** two calls answer whether evidence supports lifecycle and resource claims;
report callers learn no state-table joins or event-protocol details. **Locality:** evidence parsing,
redaction, and verdict semantics change together. Tradeoff: this deliberately cannot repair missing
telemetry or improve solving; adding arbitrary metric plugins would enlarge the Interface before
there is measured need. Recommend this small audit Module as the first evidence slice, while keeping
live scheduling, tactics, and automated submission outside this proposal.

## Scheduler implementation update

The later measured decision kept the existing `Orchestrator` seam instead of adding the proposed
audit framework. A secret-free production-path fixture compared one active challenge/two turns
(arm A) with two active challenges/four turns (arm C), over all 15 catalogue entries. Arm C took
0.1994 seconds versus 0.3597 seconds for A (ratio 0.5544), with identical outcomes, 30 attempts,
SQLite integrity `ok`, and no residual task or workspace. The pre-registered gate was ratio ≤0.70.
`scripts/scheduler_acceptance.py` reproduces the measurement. Its deliberate CLI benchmark retains
that wall-clock gate. CI passes `max_elapsed_ratio=None` because shared-runner pauses made the
sub-second ratio nondeterministic; CI instead checks the exact admission topology, all 15 outcomes,
30 attempts, cleanup, and SQLite integrity.

Selected defaults are two active challenges, two independent lanes, four lane slots, two FIFO
episodes, and one dynamic instance. Initial episode coverage precedes retries; one challenge never
has overlapping episodes; carry is lane-local; workspace capacity is partitioned across the active
set. Configuration rejects capacity that cannot admit every complete lane wave. Board-solved
metadata never skips work or contributes run-local score; `already_solved` is not a validating
verdict.

Post-implementation Daybreak/xhigh review reproduced and then drove fixes for partial-wave
admission and repeated-cancellation lease release. The final non-live suite has 286 passing tests;
96 sustainability cycles passed; the ARM64 final image is Linux/ARM64, UID/GID 10001, contains
Codex 0.154.0, and reports the selected defaults. The contributor wizard uses Docker for pinned
tool installation and supports macOS, Linux, and Windows through WSL2. No live Board/model run is
claimed by this update.

Effective routing: architecture/research `gpt-6-astra`/`xhigh`; implementation fixtures and
measurement `gpt-5.6-luna`/`xhigh`; focused testing and independent review
`gpt-daybreak-blue-latest`/`xhigh`; no fallback.

## Category-tooling decision

Organizer evidence supports deep preparation for web, pwn, crypto, reversing, forensics, and
medical/healthcare; the practice catalogue additionally exercises network and misc [B1, B2]. The
final set is distinct, but no retrieved organizer source establishes mobile, blockchain, cloud,
OSINT, hardware, or ML as IN-CYPHER categories. Build deep for the evidenced surface. Cover other
possible CTF categories only through reusable passive primitives; do not install full speculative
stacks.

The first measured slice therefore adds one source-bound artifact inspector, durable ranged
base64/hex/URL derivation, and bounded exact arithmetic. Artifact adapters cover paginated
text/strings/bytes, archives, PDF, PCAP/PCAPNG, ELF/PE, multi-architecture entrypoint disassembly,
raster/bitplanes/OCR, WAV, and DICOM with explicit complete/partial/unsupported states. Capstone is
the bounded x86/x64/ARM/Thumb/AArch64 decoder; absence is reported explicitly rather than widening
confinement through an objdump fallback. The native app-server wire sees 12 workspace tools (9,450
compact JSON bytes), or 11,282 bytes with five assigned-target tools, rather than every
compatibility operation. Installed parser distributions occupy about 29.7 MB in the host
verification environment; an intermediate ARM64 image grew 47,218,090 bytes.
Storage remains governed by the 500 GB workspace allowance, not a smaller package budget.

The selected pinned additions are Pillow, Capstone, dpkt, pefile, pypdf, and Debian Tesseract.
Build-time installation is automatic on both supported Linux image architectures and requires no
host analyzer installation. Admission still requires final-image fixtures and lifecycle review;
package presence alone is not a capability claim. Higher-value next slices are assigned-origin web
browsing, TCP reconstruction/payload derivation, deeper pwn/reversing metadata, and bounded nested
DICOM/forensic filesystem access. Broad speculative category stacks remain deferred absent evidence.

The accepted non-live snapshot passes 533 unit/interface tests (one host-skipped Linux sandbox
test), Ruff, formatting, and the deterministic scheduler benchmark at a 0.5627 elapsed ratio. The
fresh ARM64 image `sha256:e34adf8ca84e43e501e7e5cae97a96495c30e559725a80af2394c58989468510`
passed all 12 visible tools and the explicit 31-operation acceptance inventory: PCAP/PCAPNG, PE
disassembly/imports/exports, isolated TAR inventory, bounded gzip and ZIP materialization,
text/string/byte views, PDF, raster/bitplane/OCR, WAV, DICOM, x86/ARM/AArch64 Capstone, fixed ELF
helpers, and ext2 inspection. It left zero child processes, held file descriptors at 4 to 4, and
removed its temporary directory. Its integrated native ARM64 probe confirmed ABI-4 Landlock,
blocked worker and descendant sentinel reads and loopback access, allowed private scratch, denied
`setsid`/`setpgid` with `EACCES`, and verified both reported PIDs disappeared. Native amd64 x32
runtime verification is enforced by the same harness in CI; emulation is not counted as evidence.

An immutable security scan of `cc2301d24e53c173fd58e99bc80608555869fc39` found three low-severity
parser-boundary defects: supervisor-side TAR/PAX metadata parsing, amd64 x32-tagged syscalls passing
the native-number filter, and parser descendants able to detach from the cleanup process group.
The follow-up source routes TAR inventory through the existing bounded worker, rejects the x32 ABI
before allow, and denies `setsid`/`setpgid`; focused tests, native ARM64 probes, and independent
Daybreak/xhigh review pass. Native amd64 CI remains authoritative for the x32 runtime guard.

The independent final review then found encoded-reflection and over-limit path-suffix provenance
bypasses, a post-worker source-fingerprint race, mixed-endian PCAPNG and overlapping-string
pagination defects, unenforced non-Linux public worker use, supervisor-side TAR materialization, and
incomplete descendant acceptance. The integrated fixes fail target evidence closed, recheck source
facts, carry bounded continuation state, reject non-Linux production workers, restrict visible
materialization to ZIP, and verify exact sandbox PIDs. The 533-test and final-image results above are
post-fix evidence.

Effective routing for this tooling slice: architecture `gpt-6-astra`/`xhigh`; bounded fixture work
`gpt-5.6-luna`/`xhigh`; demanding implementation, independent review, and integration after an
Astra safety-filter failure `gpt-daybreak-blue-latest`/`xhigh`. Every dispatch was exact and no
provider fallback was accepted. The instruction to switch directly to Daybreak after an Astra
failure governs subsequent work.

## Immutable episode-evidence decision

Measured synthetic pressure used 15 challenges, two episodes, and two lanes: 60 attempts and 91
host events occupied 106,496 SQLite bytes. A carry envelope measured 1,194 bytes empty and 42,565
bytes with four maximal ASCII manifests. Existing wave records retained mutable model summaries
and truncated call metadata, so they could not independently preserve detailed host observations.

The selected design is a SQLite-only `RunEvidence` deep module with three public operations:
`open`, `commit`, and `carry`. Each running attempt commits a canonical, domain-separated SHA-256
manifest before its terminal transition. SQLite triggers bind the immutable manifest to
run/challenge/lane/episode identity. Reopening verifies canonical bytes, hashes, schema, limits,
relationships, candidate-sensitivity markers, and byte accounting. Legacy or crash-interrupted
terminal attempts receive an explicit empty unavailable manifest rather than invented observations.

The host projects tool results through a closed typed policy. It retains bounded structural facts
and digests while excluding raw payloads, authorities, paths, credentials, and candidate material.
Carry is deterministic, capped at 64 KiB, same-run/same-challenge/same-lane, and earlier-episode
only. It may preserve structural observations from a candidate-sensitive attempt so a disagreement
can inform the next episode, but removes candidate values, hashes, payload/object/manifest digests,
and fail-closed incomplete-scan fingerprints regardless of terminal status. The solver prompt labels it
immutable host-recorded provenance but still semantically untrusted, requires re-observation of
decisive facts, and budgets it inside the 128-KiB total prompt cap. It cannot satisfy current-turn
candidate provenance.

Post-review integration checks pass 586 tests with one platform-conditional skip on both Python
3.11 and 3.12, plus Ruff, formatting,
and whitespace validation. Effective routing: competing architecture designs
`gpt-6-astra`/`xhigh`; demanding implementation and independent review
`gpt-daybreak-blue-latest`/`xhigh`; black-box acceptance fixtures `gpt-5.6-luna`/`xhigh`. The Astra
architecture dispatch succeeded on its first attempt, so no fallback or retry occurred.

Independent Daybreak/xhigh review reproduced six initial defects and four fail-closed follow-ups.
The integrated corrections retain candidate-disagreement structure without a digest oracle, budget
all carry and Board-valid descriptions inside the total prompt cap, preserve completed observations
on cancellation across Python 3.11 and 3.12, retain safe target status/count/payload fingerprints,
scan decoded binary target payloads before fingerprint carry, reject floats before persistence, and
validate exact manifest/schema/trigger versions. Final exact-range review then reproduced three
additional fail-closed boundaries: Python 3.11 cancellation metadata loss, sensitivity lost through
quota omission, and binary/Base64 candidate fingerprinting. All three now have deterministic
regressions. A reviewer-created Sol/xhigh sublane was stopped immediately and supplied no accepted
verdict or patch. A fresh no-subdelegation `gpt-daybreak-blue-latest`/`xhigh` review then passed 14
focused regressions on both Python 3.11 and 3.12 with no remaining finding.

A subsequent immutable Daybreak/xhigh security diff scan of commit `3bceeb2` closed all four runtime
surfaces. It validated one P3 candidate-fingerprint oracle in non-candidate terminal carry and rejected
three concurrency/resource candidates with deterministic reproductions and measured bounds. The fix
persists a private fail-closed candidate-sensitivity marker before any quota omission, including
incomplete scans and decoded binary target results, and derives attempt-wide public digest redaction
from that marker rather than terminal status. The original oracle no longer reproduces across all
seven carryable terminal statuses or any quota path; ordinary structural carry retains its digests.
One Astra/xhigh threat-model attempt failed to converge and was interrupted; routing then switched
directly to Daybreak/xhigh with no Astra retry or silent fallback.

## Sources

[I11]: https://github.com/jerome-queck/incypher-rapido/issues/11
[R1]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/orchestrator.py#L1194
[R2]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/orchestrator.py#L604
[R3]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/codex_app.py#L1131
[R4]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/solver.py#L89
[R5]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/state.py#L308
[R6]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/orchestrator.py#L925
[R7]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/codex_app.py#L97
[R8]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/codex_app.py#L852
[R9]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/tools.py#L1469
[R10]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/notes/research/dynamic-acceptance-2026-09-15.md#L8
[R11]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/codex_app.py#L1007
[R12]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/codex_app.py#L1305
[R13]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/notes/research/implementation-audit-2026-09-15.md#L3
[R14]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/Dockerfile#L16
[R15]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/deploy/CONTAINER.md#L28
[R16]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/cli.py#L37
[R17]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/notes/research/sustainability-acceptance-2026-09-15.md#L38
[R18]: https://github.com/jerome-queck/incypher-rapido/blob/2f97c9641f01f68c3b478a08fb2bb034a4e5bfa9/rapido/state.py#L21
[O1]: https://learn.chatgpt.com/docs/app-server#protocol
[O2]: https://learn.chatgpt.com/docs/app-server#start-or-resume-a-thread
[O3]: https://learn.chatgpt.com/docs/app-server#start-a-turn
[O4]: https://learn.chatgpt.com/docs/app-server#steer-an-active-turn
[O5]: https://learn.chatgpt.com/docs/app-server#interrupt-a-turn
[O6]: https://learn.chatgpt.com/docs/app-server#trigger-thread-compaction
[O7]: https://learn.chatgpt.com/docs/app-server#events
[O8]: https://learn.chatgpt.com/docs/app-server#unsubscribe-from-a-loaded-thread
[O9]: https://learn.chatgpt.com/docs/app-server
[O10]: https://learn.chatgpt.com/docs/auth/ci-cd-auth
[B1]: https://hackathon.in-cypher.com/how-to-play
[B2]: https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/
