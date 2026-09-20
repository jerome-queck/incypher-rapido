# Capability sprint execution ledger

## CAP-01 — complete

- Branch: `codex/capability-sprint-cap01`; base `6aa26147c35fbc46affeeb77d93d6b88640564a8`.
- Handoff validation: pass. Exact archive/task-manifest commitments are in the CAP-01 registration.
- Source refresh: clean and equal to `origin/main`; no open pull request at refresh.
- Read obligations: prompt; full ordered handoff; urgent override/locked facts; issue #19 and all 35
  comments; repository container/dynamic evidence; current source seams.
- Source research: design and historical remote SHAs match frozen identities. Dirty later design
  checkout excluded from evidence.
- Private setup: curator/runner/oracle/run/output classes created owner-only; parent-removability and
  synthetic exact-delete probe passed. No private path is public.
- Runtime: host native client failed before initialization because its 0.153.2 catalogue lacks one
  current strict feature flag. Exact clean ARM64 image with 0.154.0 built and passed catalogue-only
  Daybreak/xhigh, Luna/max, and Luna/xhigh checks. No model turn or scored task ran. Preflight
  container residue: zero.
- Delegation: handoff and Board-seam Daybreak/xhigh reviews completed; reviewers could not
  independently introspect their effective descriptors. Astra/xhigh architecture review failed
  with provider 403 and was recorded without silent fallback. The owner authorized
  Daybreak/xhigh as the explicit Astra fallback; that separately registered architecture review
  completed read-only.
- Handoff review findings: schema cross-field gaps, sentinel tier ambiguity, and pseudo-node DAG
  tokens are corrected by the CAP-01 public validator/registration interpretation.
- Public artifacts: registration, experiment registry, receipt schema, pure validator, focused
  schema/privacy tests, CI schema-validator pin, this ledger.
- Private artifacts: exact handoff registries and task assignments; credential copy; descriptor
  preflight; path/mode inventory. None enter Git.
- Failures/skips retained: host descriptor startup failure; Astra peer failure. No Board access,
  scored work, official practice evaluation, candidate use, or challenge-answer search occurred.
- Independent review found and drove fixes for bundled sentinel/schema gaps, incomplete nested
  receipt validation, host-path/authority bypasses, mutable source/scheduler/roster/denominator
  contracts, post-cap work, contradictory terminal/evidence rows, service readiness, timeline
  snapshots, and sentinel score inflation. Two final no-edit reviews found no surviving actionable
  correctness, privacy, schema, scope, or deployability defect.
- Final verification: canonical registration and exact scheduler/source/image/task commitments;
  Draft 2020-12 receipt meta-schema and canonical/adversarial examples; exact 870-row private
  manifest; 56 focused schema/config tests; 129 schema/config/supervisor tests; 1,411 full-suite
  passes with four documented skips; full Ruff lint/format; PR80 private-parent tests; clean
  diff/secret/privacy scan. Exact image remains ARM64 with `rapido run` as entrypoint and zero
  retained run containers.
- PR #82 passed all required CI and was squash-merged to `main` as
  `0c63ae1ba2fd4ee1d2aace97842fc242ed6ab0b3`. The retained production ARM64 image identity is
  recorded in the CAP-01 registration; no container remained running.

## CAP-02 — active

- Branch: `codex/capability-sprint-cap02`; base
  `0c63ae1ba2fd4ee1d2aace97842fc242ed6ab0b3`.
- Registered implementation lane and independent review lane: exact
  `gpt-daybreak-blue-latest` / `xhigh`; no fallback.
- Added a structural `BoardLike` annotation over the already-existing dependency-injection seam.
  Production `BoardClient`, origin parsing, target parsing, CLI, defaults, and Dockerfile remain
  behaviorally unchanged.
- Added a separate folder-backed `OfflineBoard`, explicit offline config adapter, credential-free
  native-runtime builder, direct-injection runner, and dedicated offline script. No loopback Board
  transport shim was needed.
- File boundary: descriptor-relative source reads; pinned bank/workspace roots; traversal,
  alternate-root, symlink, hard-link, FIFO, socket, device, mutation, size, and destination-race
  rejection; bounded same-directory atomic copy.
- Candidate boundary: exact-byte private run cache, monotonic public ordinal, one deterministic
  checker call per unique value, cached repeats, and closed `oracle_inconclusive` on checker failure.
  Candidate bytes are erased on close and never projected publicly.
- Service boundary: controller-generated loopback-IP endpoints only, one global lease,
  GET/POST/PATCH/DELETE normalized six-key records, partial-create cleanup fencing, retry-on-close,
  and post-delete absence proof.
- EAS-005: unchanged durable controller, source-bound two-stage verification, one deterministic
  correct submission, `submission_http_200_correct=1`, `run_local_verified=1`, exact cleanup.
- EAS-006: unchanged durable controller, two fresh service generations, two actual assigned-target
  HTTP observations, one deterministic correct submission, create/delete/absence proof, one-lease
  peak, exact cleanup.
- Cancellation acceptance: active dynamic work was cancelled; native runtime closed; service,
  workspace, SQLite state/sidecars, and native lock were absent afterward.
- Freshness/privacy: two independent fresh runs had distinct identities and empty initial
  solved/cache/service state. Sanitized receipts contain no candidate, candidate digest, private
  path, target authority, credential, raw model output, or raw tool output.
- Implementation checkpoints: `0349768a7b5e554d14996cea7ba756dab610139f`; Linux cleanup fix
  `05e8c7db02a055b01448a656c16c31282932f00d`.
- Current evidence: 117 CAP-02 focused tests; 46 Board-contract tests; 316 affected
  Board/CLI/config/container/control/orchestrator/target tests; 1,528 full-suite passes with four
  documented skips; Ruff and format clean. One earlier full-suite
  run was deliberately invalidated and interrupted after 732 passes, one skip, and one deselection
  because a cleanup proof changed during the run; it is not counted as verification. Sanitized stage evidence is
  `notes/research/offline-board-acceptance.json`.
- Failures retained: the first local command used unavailable `python`; `.venv/bin/python` was used.
  Intermediate test failures exposed and fixed unsafe partial-service cleanup, non-loopback service
  acceptance, candidate-result constructor drift, the 600-second admission floor in synthetic
  tests, fixture portability, Docker kill/reap races, and Darwin directory unlink semantics. The
  final Daybreak/xhigh independent review reproduced the real-Docker, cleanup-race, per-task receipt,
  and exact file/directory substitution evidence and found no remaining actionable defect. No
  official Board, scored task, candidate reuse, or answer search.
- First PR #83 CI run: both Python jobs failed together (12 failures each, with 15 skips)
  because Linux reports a removed pinned directory with `st_nlink=0` while the proof required one
  exact `/proc/self/fd` display suffix. The failure cascaded into retained run roots and dependent
  receipt tests. Linux now uses the inode unlink proof; Darwin retains `F_GETPATH`. Container jobs
  were still running when the focused fix was pushed.
- Next ready node: commit the bound sanitized receipt, PR/CI/merge; then
  continue CAP-03/CAP-04 private trust-zone work and CAP-05 runner work. Stage 4 remains blocked on
  the fresh-task readiness quorum.
