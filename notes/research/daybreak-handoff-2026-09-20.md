# Daybreak engineering handoff — 20 September 2026

This is an engineering readiness record, not an organizer submission rubric or a claim of
competition readiness. All new execution evidence is local and synthetic unless stated otherwise.

## Source and access

- Rapido baseline: `350d4229add2d8e55b279b64cbba1eeadef494cc`, default branch `main`.
- Read-only reference: `892c764ba65751af31c59386e27fdf05523e162e`, default branch `main`.
- Fresh isolated checkouts had no pre-existing edits. No open Rapido PRs were returned initially.
  Before the state slice, PR #86 appeared: documentation for a solver-tooling pivot. It merged
  during validation as `d93e090e4d10fa7a179b8bb270d69ed670b60b48`. It changes no runtime behavior;
  the patch sequence must also be checked against those current documentation changes.
- GitHub CLI and connector both identify `n0nsense00`; repository permission is `READ`.
  Local commits and patch delivery are possible; upstream feature-branch writes are unavailable.
- Requested Daybreak/xhigh audit lanes failed with missing `access_programs.cyber=daybreak_blue`,
  including fresh sessions after the user enabled access. Independent Daybreak review and
  model-dependent evaluation have not run. No alternate solver model was substituted.
- No Board credentials, authenticated catalogue, approved team environment, or practice/live run
  configuration was supplied for this work. No authenticated Board reads, deployments, challenge
  execution, submissions, organizer messages, or active deployment changes were performed.

## Organizer contract and runtime evidence

The [technical guide](https://hackathon.in-cypher.com/how-to-play), retrieved on 20 September,
still gives competition opening at 22 September 10:00 SGT and closing at 23 September 18:00;
ADK release is listed as 21 September 10:00. The indexed
[Imperial agenda](https://www.imperial.ac.uk/about/global/singapore/research/in-cypher/in-cypher-hackathon/hackathon-agenda/)
instead lists a 22 September 10:30–16:00 competition and a 14 September starter pack.
Direct Imperial retrieval returned HTTP 403. These conflicting schedules are unresolved.
The public challenge page did not provide a qualified catalogue. The official helper's
`solver.connect` interface is documented, but no new ADK package or helper implementation was
available to validate here. Existing repository observations remain historical evidence.

Use an organizer-confirmed externally supplied run budget, not either page's conflicting cutoff.
`RAPIDO_RUN_SECONDS` already controls admission and the durable start preserves its deadline on
crash recovery. The default 19,800 seconds is a repository setting, not organizer confirmation.
Exact deployment, scoring, helper, response/reconciliation and packaging contracts remain open.

The host Windows and WSL Codex executables are 0.149.1. A separate official npm package
`@openai/codex@0.154.0-linux-x64` was downloaded without installation scripts (SHA-1
`9e93bbf0906338c2d1ebbeb9de3b0a4ef7123e55`; npm also verified its SHA-512 integrity).
Its binary reported 0.154.0 and generated its version-specific JSON schemas. The exact repository
`APP_SERVER_ARGS` completed `initialize` / `initialized` with a temporary empty authentication
home, explicit minimal environment, zero model turns and zero Board calls. It exited zero.
The host lacked system bubblewrap; the binary reported using its bundled helper. This handshake
does not validate a model, account, sandboxed turn, container, or competition target.
See [OpenAI app-server documentation](https://learn.chatgpt.com/docs/app-server) for the handshake
and version-specific schema generator.

## Capability matrix at the starting SHA

| Requirement | Implementation and covering tests | Observed behavior / verified gap |
| --- | --- | --- |
| Board ingestion and read-only preflight | `rapido/board.py`, `rapido/cli.py::_preflight`; `tests/test_board.py`, `tests/test_cli.py` | Fixed official origin; repeated identity/catalogue qualification. The added full fake-preflight test traps Board mutations, native startup and state-writer creation. |
| Native authentication and model selection | `rapido/config.py::validate_codex_home`, `rapido/cli.py::_codex_child_env`, `rapido/codex_app.py::validate_model`; config/CLI/native tests | Dedicated writable native home, allowlisted environment, exact catalogue/effort and no provider fallback. Competition account/model entitlement remains unverified. |
| Native RPC lifecycle | `rapido/codex_app.py`; `tests/test_codex_app.py` | Existing 121 tests pass. New fakes reproduce unbounded write-lock/drain waiting before the RPC timeout and unbounded silent initialization. Interrupt writes can stall process fencing. |
| Container / tools | `Dockerfile`, `deploy/CONTAINER.md`, `scripts/setup_container.sh`, `.github/workflows/ci.yml`; container/tool tests | Digest-pinned bases and Codex 0.154.0, non-root runtime, external state/auth. Docker unavailable on this host: no build or image startup claim. Windows CRLF conversion breaks immutable fixture hashes and shell portability. |
| Target and credential boundary | `rapido/target.py`, artifact/analysis worker modules; target, artifact-sandbox and worker tests | Exact Board-issued target registry; supervisor retains team key; bounded PoW and isolated parsers. Compatibility with the newly released official helper remains unverified. |
| Instance identity and recovery | `rapido/orchestrator.py`, `rapido/state.py`; stale-generation, owned-instance and supervisor tests | Durable create/cleanup intents and generation receipts; replacement mismatch fails closed. Undocumented inactive responses remain unresolved; no new live validation. |
| Candidate provenance | `rapido/evidence.py`, `rapido/codex_app.py`, `rapido/state.py`; evidence/taint/integration tests | Source-bound evidence and independent verification already exist. Candidate/model assertions alone do not become Board acceptance. |
| Artifact content identity | `rapido/artifact_inspector.py::_verified_source`; artifact inspector/worker tests | Same-size rewrites can leave metadata unchanged. Added a streamed content recheck before returning any successful view; changed bytes now fail with `source_changed`. |
| Durable submissions | `StateStore.reserve_submission`, `BoardClient.submit`, `_submit_candidate`; state/orchestrator/Board-contract tests | Intent precedes send; settled verdicts require matching body/status; ambiguous outcomes remain pending and require explicit reconciliation. No exactly-once guarantee or invented server idempotency. |
| Phase and content identity | `RuntimeConfig.profile`, `StateStore.start_or_resume_run`, control catalogue material hashes; state/control and `test_state_phase.py` | Reproduced prior-phase pending intents visible after a terminal run allowed another phase to start. The new guard checks every recorded Board/profile before recovery or Board calls, preserves old evidence and requires fresh state for a different scope. |
| Scheduling / compact memory | `rapido/orchestrator.py`, `rapido/routing.py`, `rapido/memory.py`; scheduler/control/memory tests | Initial coverage, bounded lanes, original deadline and material-scoped notes already exist. Default P20 is established repository policy; this work has no measurement authorizing a larger framework or different roster. |
| Quota / access errors | failure classes in `rapido/codex_app.py`, routing and supervisor; routing/runtime tests | Classified usage/auth failures and bounded replacement already exist. Reset-aware scheduling via actual account limits is not implemented or validated by this slice. |
| Evaluation | `rapido/board_contract.py`, offline H24 and sustainability scripts; synthetic harness tests | Existing fake Board and held-out fixture infrastructure is reusable. Synthetic correctness is not real CTF solving ability. Model/target evaluation remains unmeasured. |

Reference inspection covered `solver/submission/reconciliation.py`, `solver/submission/ledger.py`,
`solver/instance_ledger.py`, `solver/route_and_quota.py`, and its conformance/tool-supply inventory.
Its broker-owned reconciliation and classified quota observations are useful design comparisons;
the alternative inference route is incompatible with the requested native-only architecture.
The reference reserves current source rights. No reference code was ported or modified.

## Validation and remaining release work

The runtime slice puts lock acquisition, pipe drain and response wait under one RPC budget.
The default is 30 seconds, with a separately classified local RPC failure; an explicit shorter
interrupt budget still produces `TimeoutError` and reaches process fencing. Notifications and
server replies also have bounded writes. Closing a client while a writer is queued produces a
closed-client error and consumes orphaned response exceptions. Native turn RPC failures fence
uncertain execution before the workspace can be retired.

Four new deterministic regressions failed before this fix: blocked lock, blocked drain, silent
initialization and blocked interrupt. The response-only control already passed. Additional tests
cover invalid deadlines, concurrent close, bounded notifications and read-only preflight.
The supervisor shutdown test now waits for its durable terminal record before sending SIGTERM;
its previous 200 ms import-speed assumption produced exit -15 in this WSL checkout.
Git attributes preserve LF in text, including shell scripts and hashed protocol fixtures.

The state slice reuses stored run configuration instead of adding a database migration. The
scope check executes transactionally before recovery changes or new run insertion. Terminal
practice state cannot be reused for competition, even when Board URL and challenge IDs match.
Unknown, partial or mixed legacy scope fails closed; same-scope crash recovery retains its
original run identity and start time. The operator must configure the correct profile: this
does not discover an organizer's phase automatically or identify a new event within one label.
Nine initial synthetic regressions yielded eight failures before the guard and all passed after
it; the focused state suite passed 73 tests. Full-suite and final results are in the handoff.

Full clean-baseline validation completed with 1,606 passed, 31 skipped and seven failures in
176.31 seconds using temporary in-memory fixture storage. Five failures require unavailable
Docker, one is the existing media in-place source-change test, and one is the supervisor test
race fixed here. This storage choice avoids WSL journal latency; it does not prove power-loss
durability, container readiness or solving performance. Scheduling changes remain deferred
until the core loop, environment and independent review gates are dependable.

The combined runtime/state suite completed with 1,630 passed, 31 skipped and six failures in
218.67 seconds; all six also failed on the clean baseline. No new test failure was observed.
The media failure was independently reproduced: a same-size rewrite left metadata unchanged,
so returned parser output carried the old content hash. The artifact follow-up verifies bytes
and metadata at the end of every successful view, including byte/text views and isolated parser
results. Three deterministic regressions fail before the fix; all 96 artifact inspector/worker
tests pass after it. This adds one streaming hash pass per successful inspection, bounded by the
existing 256 MiB source ceiling. It detects the reproduced persistent mutation; it is not an
immutable snapshot or a guarantee against an adversarial writer that changes and restores bytes
between checks. Artifact tooling performance is unmeasured. No category tooling or scheduler
change was made. Ruff and format checks pass for the combined sequence.

Exact final commands/results and commit identities accompany the delivered handoff report.
No live solve/point, model-token, model-call, competition-duration, or intervention improvement
is claimed. Any such value is unknown. Deterministic no-socket regression evidence is reported
separately from native initialization and from unperformed container/model evaluation.

Before release: obtain write permission and independent review; build and identify the final
image on a supported Docker host; verify the approved dedicated ChatGPT account and exact model
catalogue/effort; obtain the organizer's definitive ADK/helper/response/packaging contract and
deadline; supply a separately authorized practice/live configuration and empty private state;
run read-only preflight before authorizing the autonomous run. Preserve sanitized diagnostics,
private durable state for crash recovery, and the previously approved image for rollback.
