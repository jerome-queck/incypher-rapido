# Implementation audit — 2026-09-15

> Historical baseline at commit `15b5813`. Its present-tense gap conclusions are superseded by the
> post-audit implementation and acceptance result below; the original text is retained as an audit
> trail.

## Post-audit implementation and acceptance result

- Dynamic lifecycle, fixed-authority HTTP/TCP, supervisor-held team-key PoW, receipt-bound cleanup,
  transport-only retries for idempotent Board reads, strict candidate provenance, closed native
  failure classification, one-active-tool-per-turn admission, cancellation-safe app-server cleanup,
  and expanded artifact tools were implemented and independently reviewed.
- One exact-final-image whole-catalogue run qualified all 15 challenges, skipped the solved one, and
  completed all 14 remaining two-lane waves with real tools and zero errors. One earlier container
  autonomously made the single qualified correct submission; no operator entered or relayed an
  answer.
- Accelerated evidence now includes 1 hour 3 minutes 43 seconds of exact-final-image catalogue work,
  nine dynamic create/ready/remove cycles, exact-image SIGTERM during an active target, exact-image
  SIGKILL plus durable restart recovery, and the 96-cycle synthetic harness. See
  [dynamic acceptance](dynamic-acceptance-2026-09-15.md) and
  [sustainability acceptance](sustainability-acceptance-2026-09-15.md).
- The final tested image is
  `rapido@sha256:e8c14d8e28ddfbefcc5cc96571e2d382eccfdc654f8140d0948ab10d95a28ebb`,
  built from runtime commit `673bddc`; 240 tests, Ruff, formatting, and whitespace checks pass.
- The organizer starter/ADK and final packaging/startup contract remain unavailable. The documented
  narrow Board generation read/delete race also remains because the Board exposes no atomic
  conditional-delete operation. No full 5.5-hour rehearsal is claimed.

## Scope and evidence

Read-only source audit of commit `15b58136200ec805233bbaec3194df60074c695a`, plus local secret-free tests. Only this report was added. No credentials, private Board data, existing runtime databases, authenticated model sessions, or challenge endpoints were accessed. No final image was built or exercised in this lane. External-contract and real-service claims remain unverified here.

Assigned audit worker: inherited parent model and reasoning settings; exact runtime identifiers were not exposed to this worker. The developer context identifies the Codex model family as GPT-6, which is not sufficient evidence of an exact deployed model or reasoning effort. Do not substitute the solver's configuration defaults for the audit worker's actual settings.

Results:

- `.venv/bin/python -m pytest -q`: **111 passed, 1 failed**, 0.74 seconds. `tests/test_tools.py:292` expected empty stderr from the system `python3`; macOS emitted a `confstr()` warning inside the restricted environment. Bounded stdout length and return-code assertions passed. This is a local environmental discrepancy; no Linux result is inferred.
- `.venv/bin/ruff check rapido tests scripts`: passed.
- `.venv/bin/ruff format --check rapido tests scripts`: passed, 20 files.
- Initial tracked worktree was clean. Tests use fake Board/native transports; passing tests do not establish final-image, real-model, or real-Board acceptance.

## Architecture map

| Component | Observed implementation | Evidence |
|---|---|---|
| Startup | CLI validates config and private native auth-home metadata; constructs one Board client, SQLite store, and shared Codex process client | `rapido/cli.py:128` |
| Queue | One qualified catalogue snapshot; challenges handled serially; one lane wave per eligible challenge; exits after exhaustion | `rapido/orchestrator.py:749`, `:751`, `:793` |
| Concurrency | Semaphore controls simultaneously active lanes; separate artifact copy and native thread per lane | `rapido/orchestrator.py:167`, `:348`, `:538`; `rapido/codex_app.py:960` |
| Inference | Native stdio app-server; initialize handshake, paginated exact model/effort validation, ephemeral threads, structured turns | `rapido/codex_app.py:400`, `:922`, `:998`, `:1033` |
| Tool boundary | 15 canonical workspace-confined tools; host dispatch; structured errors and size ceilings; fixed command arguments | `rapido/tools.py:1173`, `:1274`, `:1373`; `rapido/codex_app.py:665` |
| Board | Fixed official origin in config; authenticated reads, same-origin downloads, typed verdicts, generic instance-method wrapper | `rapido/config.py:89`; `rapido/board.py:178`, `:237`, `:299`, `:340`, `:366` |
| Durable state | Runs, current challenge states, attempts, events, submission intents/verdicts, instance receipts; SQLite WAL and private file permissions | `rapido/state.py:21`, `:69` |
| Recovery | Exclusive state/auth/work leases; active attempts become interrupted; running challenges become queued; recognized stale work roots cleaned | `rapido/state.py:143`, `:555`; `rapido/orchestrator.py:400`, `:709` |
| Packaging | Python 3.12 Debian image, pinned Codex 0.154.0, architecture-specific npm package, UID/GID 10001, `rapido run` entrypoint | `Dockerfile:3`, `:16`, `:30`, `:58`, `:72` |

The model subprocess receives an explicit environment without Board credentials (`rapido/cli.py:37`). App-server shell, browser, app, computer-use, nested-agent and other capabilities are disabled (`rapido/codex_app.py:30`). Thread startup requests read-only sandbox, no approval, ephemeral storage, and no provider fallback (`:998`). These are source controls; final runtime enforcement remains an acceptance requirement.

## State, results, and failure semantics

Attempt states distinguish `candidate`, `unsolved`, `timeout`, `cancelled`, `interrupted`, `failed`, and `unsupported` (`rapido/state.py:283`). Supervisor recovery requires a lease and updates interrupted records transactionally (`:555`). Attempt completion is a single allowed transition from running (`:296`). Events have a 128 KiB encoded limit (`:308`).

The database deliberately stores candidate text in private attempt rows (`rapido/state.py:298`); submission tables store fingerprints (`:448`). README explicitly warns against publishing state (`README.md:100`). The test named “persist without plain candidate” only checks the submissions row, not the database (`tests/test_orchestrator.py:260`, `:273`). Public reporting must never copy arbitrary attempt rows or model summaries.

Timeouts and cancellation invoke turn interruption, then fence the shared app-server if terminal confirmation is unavailable (`rapido/codex_app.py:1222`). Client close cancels tasks, terminates/kills the direct process, and clears registries (`:1366`). A later solve can restart a fenced client (`:1173`). One lane's setup failure or failed interruption can close the shared process and therefore disrupt its peer; this topology needs measured fault evidence.

SIGTERM cancels the orchestrator task (`rapido/cli.py:20`). Per-challenge cleanup is in a `finally` block (`rapido/orchestrator.py:789`), but uses `shutil.rmtree(..., ignore_errors=True)` (`:382`), so removal failure is silent. Current run-root removal is deferred until a later startup; per-challenge directories are intended to disappear immediately.

## Configuration effectiveness

| Control | Finding |
|---|---|
| Model / effort | Defaults `gpt-5.6-luna` / `xhigh`; passed explicitly and matched against `thread/start` response. Requested settings are stored; returned settings are checked but not retained as separate durable evidence (`config.py:148`, `:195`; `codex_app.py:1017`; `orchestrator.py:435`). |
| Concurrency | Effective semaphore, despite README calling it reserved. Raising it beyond lane count has no effect because challenges remain serial (`orchestrator.py:167`, `:538`, `:751`). |
| Attempts | Effective number of independent lanes and workspace copies, range 2–8. It is not a retry count (`config.py:175`; `orchestrator.py:348`). |
| Attempt/run seconds | Effective admission/turn deadlines. Shutdown may extend beyond them while worker threads drain (`orchestrator.py:169`, `:425`, `:710`). |
| Artifact/workspace bytes | Effective source/copy/tool caps. Do not cap SQLite/auth storage or all process memory (`orchestrator.py:327`, `:345`; `tools.py:1373`). |
| Submission controls | Enable switch and global wrong/indeterminate-effect ceiling are effective (`orchestrator.py:612`, `:624`). There is no global one-submission authorization budget. |
| Profile | Parsed and logged only; no behavioral use (`config.py:155`, `:235`). |
| Manage dynamic instances | Parsed and logged only; no behavioral use (`config.py:215`, `:238`). |
| Team key | Validated and presence logged; never used (`config.py:139`, `:240`). |
| Host resources | Compose example specifies 2 CPUs, 2 GiB RAM, 256 PIDs; no storage quota in template (`deploy/docker-compose.example.yml:24`). No enforcement evidence from a running container was collected. |

## Capability gaps against the objective

### Dynamic lifecycle

Every non-`standard` type is rejected before solving (`rapido/orchestrator.py:766`). The model prompt also explicitly excludes live services (`rapido/solver.py:56`). There is no runtime endpoint authority object, HTTP/TCP observation tool, PoW/team-key operation, create/readiness loop, or lifecycle sweep. The generic Board wrapper's existence is not lifecycle support.

Existing instance recovery never issues DELETE. Missing/indeterminate receipts become manual reconciliation; matching receipts also become manual reconciliation because no generation-conditional delete is available (`rapido/orchestrator.py:184`). A mismatched receipt becomes `removed` with `skipped_replaced` evidence (`:226`), which means ownership was relinquished, not that a remote deletion occurred. No dynamic reachability, concurrency limit, or teardown claim is supported by this audit.

### Artifact work

The registered tools cover listing/stat/hash, bounded bytes/text/search/strings, Base64/hex/URL decoding, ZIP/TAR listing/extraction, common image dimensions, WAV/AIFF metadata, and binary headers/symbols (`rapido/tools.py:1173`). Image handling has no DICOM support or pixel analysis (`:897`); audio has metadata only (`:973`); binary inspection is fixed header/symbol/string output (`:1015`). No signal-analysis or cryptographic computation tool is registered.

`SolverFinding` accepts evidence and next steps (`rapido/solver.py:69`), but orchestration persists only summary/candidate/confidence plus a truncated tool-call audit (`rapido/orchestrator.py:500`, `:579`). Hypotheses, verification results, next steps, and detailed observations are not durably available after cleanup. An `unsolved` result can have zero tools, empty evidence, and empty next steps (`rapido/solver.py:100`); only candidates require observed tool provenance (`rapido/orchestrator.py:486`). A nontrivial attempt on every challenge is therefore neither enforced nor demonstrated.

### Submission and autonomy

Exact agreement by two lanes, placeholder/prose filtering, and successful source-bound candidate observations are enforced (`rapido/solver.py:151`; `rapido/orchestrator.py:486`). Confidence affects tie-breaking but has no admission threshold (`solver.py:171`). There is no fresh eligibility/rules check immediately before submission: the catalogue's earlier attempts/max-attempts values are reused (`orchestrator.py:636`).

Submission intent is committed before the write, and a transport exception leaves it pending (`orchestrator.py:663`). However, an unread response is finalized as `unread` (`rapido/state.py:431`), while both pending listing and reconciliation require exactly `pending` (`:370`, `:398`). Consequently, that ambiguity disappears from the supplied reconciliation interface, remains a risk count (`:493`), and cannot be resolved there. The existing ambiguity test covers a thrown transport error, not this returned-unread branch (`tests/test_orchestrator.py:454`).

There is no Board retry/backoff policy. HTTP failures raise sanitized errors (`rapido/board.py:202`); catalogue failure aborts the run, artifact failure marks a challenge error, and the single-pass queue does not revisit it (`rapido/orchestrator.py:529`, `:749`). Rate-limit headers such as Retry-After are not retained in `HttpResponse` (`board.py:33`). Queue exhaustion ends the process; no replenishment loop exists.

### Sustainability and evidence

- Successful thread/workspace registries accumulate until process close: inserted at `rapido/codex_app.py:1026`; turn finalization removes turn maps only (`:1134`); registries clear at session teardown (`:1347`). Growth is bounded by the current finite catalogue/lane caps, but no plateau is proven. A future repeating queue would require explicit retirement.
- Direct child termination is implemented; descendant/process-group cleanup and forced-kill confirmation have no measured evidence. `close()` suppresses kill/wait timeouts then drops the process reference (`codex_app.py:1403`).
- Worker cancellation drains Python threads. Socket timeout is not an absolute whole-operation deadline: redirects repeat requests and urllib body reads may continue with arriving data (`board.py:123`, `:127`, `:379`). The README's “at most 15-second” drain claim is stronger than source guarantees.
- Per-call/turn limits exist, but state event history has no retention budget; no resource sampler or conservative 5.5-hour projection exists in the audited source.
- `scripts/native_acceptance.py:47` covers two synthetic offline lanes and optional forced timeout/recovery. It does not exercise the Board, full catalogue, submission, resource pressure, SIGTERM/restart, or accumulated-leak gates.
- Unit overlap measures outer solve interval overlap (`orchestrator.py:109`), not independently observed backend inference overlap. Final-image native telemetry remains required.

## Bounded safe implementation slices

These are infrastructure, observability, and offline verification slices; they do not prescribe autonomous exploitation or third-party attack workflows.

1. **P1 — Honest config and outcomes.** Reject/remove reserved settings; document lane-vs-challenge concurrency accurately; distinguish failure classes and make completed-with-errors visible. Acceptance: focused config and terminal-report tests; no silent success with infrastructure failure.
2. **P1 — Durable attempt evidence.** Persist sanitized hypotheses, verification actions, observations, next steps, tool counts, and runtime-confirmed model/effort; separate private details from public reports. Acceptance: restart/reopen retains meaningful evidence for offline synthetic work; reports contain no private candidate content.
3. **P1 — Ambiguity accounting.** Make every indeterminate submission outcome visible to read-only inspection and explicit reconciliation while preserving no-repeat behavior. Acceptance: returned-unread, timeout-before-response, and restart cases remain inspectable without additional Board writes.
4. **P1 — Cleanup truthfulness.** Report deletion failures; retire finished thread registries; retain process ownership until confirmed exit. Acceptance: fault-injected cleanup failures are durable and detectable; repeated offline lifecycle cycles plateau in registries, tasks, descriptors, and child counts.
5. **P1 — Bound read-only transport operations.** Separate wall-clock operation deadlines from socket inactivity timeout; classify transient errors and surface retry metadata. Acceptance: fake-server trickle/redirect/rate-limit fixtures terminate within their budgets and preserve truthful outcomes.
6. **P2 — Offline acceptance harness.** Add time-compressed, synthetic process-failure/SIGTERM/restart/resource sampling around the existing bounded offline mode. Acceptance: no stuck slots, coherent reopened state, measured growth slope with safety margin; explicitly exclude real-Board and 5.5-hour-runtime claims.
7. **P2 — Packaging proof.** Pin the tested artifact digest, verify actual architecture/entrypoint/mount/resource behavior, and inventory licenses/notices. Dockerfile has no explicit healthcheck or project notice packaging (`Dockerfile:30` onward; `pyproject.toml:5`). Organizer requirements require separate first-party verification.

## Acceptance conclusion

The repository contains substantial bounded offline orchestration and defensive state/tool controls. It does **not** establish the supplied competition outcome: dynamic lifecycle is absent, catalogue work is single-pass, useful-work evidence is incomplete, submission ambiguity has a reconciliation gap, and accelerated sustainability/final-image acceptance remains unproven. No full 5.5-hour rehearsal occurred in this audit.
