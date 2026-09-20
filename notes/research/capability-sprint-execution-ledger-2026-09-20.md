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

## CAP-02 — complete

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
- Implementation checkpoints: `0349768a7b5e554d14996cea7ba756dab610139f`; Linux cleanup fixes
  `05e8c7db02a055b01448a656c16c31282932f00d` and
  `8074f365202007fc9d3e8d6b541ef3232ad62911`.
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
- Three PR #83 CI attempts exposed the same 12 cascading Python failures. Investigation first
  hardened Linux directory unlink proof and passed an exact registered-image Linux probe, but the
  actual CI cause was earlier: GitHub exposes Docker while lacking the frozen image digest, and the
  end-to-end acceptance tests had no digest-availability skip. The image-dependent cases now record
  a documented skip when that exact image is absent; local registered-image acceptance remains
  117/117. Both container architectures passed in the first completed CI run.
- PR #83 passed Python 3.11/3.12 and amd64/arm64 container gates and was squash-merged to `main` as
  `735d295ee078a0ce728613800b715cc458f6869f`.

## CAP-03/CAP-04/CAP-05 — active

- CAP-03 public capsule/exporter and CAP-05 completion-runner seams were implemented on focused
  additive files with independent Daybreak/xhigh review. First review rounds rejected both rather
  than accepting green synthetic tests: CAP-03 had archive/assignment/bounded-parser/cleanup issues;
  CAP-05 lacked concrete unchanged-flow integration, enforced caps, deep receipt validation, and
  bounded settlement/cleanup semantics.
- Later CAP-03 reviews rejected successive green suites: a host subprocess could not prove kernel
  network/filesystem isolation; malformed, high-ratio, concatenated, and arbitrary-prefix polyglot
  archives could false-pass; ancestor and final-name substitutions could redirect or delete foreign
  objects; public metadata could expose private markers; incomplete registry rows admitted mutated
  task behavior; and ambiguous OCI creation could hide residue. The final exact-source implementation
  (`b22ab76670a8b6f1e78a7e9be494a1b86122ad6c756f968692d2b434ef944ccd`; tests
  `bca931e2d0d2f385994ac223170c23c79a4793392bc6c68858211b166651c79c`) requires a disposable
  networkless OCI worker, full private task bindings, operation-labelled ID-only OCI reconciliation,
  bounded recursive archive classification, and descriptor/quarantine cleanup. Independent review
  replayed every prior bypass and passed 105/105 tests against exact image
  `sha256:89300f5c36167e77cd5292e2fb5bdde1841eb2a8bd0f0854a39811d575454d34`; CAP-02/CAP-03
  integration passed 152/152. Ruff, format, compilation, diff, labelled-container/volume absence,
  and private PWN preservation passed. POSIX deletion cannot be inode-atomic against arbitrary
  synchronous same-EUID syscall interposition; the registered boundary therefore excludes untrusted
  same-EUID host execution, runs hostile bytes only in OCI, and preserves/fails closed on every
  injected substitution hook. CAP-05's later passes addressed an outer/inner deadline split,
  repeated cancellation cleanup, exact experiment binding, lower-bound usage caps, privacy
  patterns, terminal/evidence biconditionals, and finally a disposable process supervisor.
- Private CAP-04B admitted fresh owned `REV-A` and `REV-B`: six V1–V3 validations and four Tier-A
  calibration siblings passed independent references; 40 wrong/near-miss/decoy/canary cases
  rejected; four capsules passed candidate-free CAP-03/CAP-02 integration; residue and leak counts
  are zero. No historical material, model call, scored solver, official Board, or network was used.
- Private CAP-04D admitted fresh owned `CRY-A` and `CRY-B` under the same boundaries: six V1–V3
  validations and four Tier-A siblings passed exact/unique and hardness-band checks; 40 negative
  cases rejected; candidate-free capsule/Board integration and exact cleanup passed with zero leak
  or residue.
- Private CAP-04E admitted fresh owned `FOR-A`: three V1–V3 validations and two Tier-A
  calibration siblings passed references, rebuild/scanner/tool gates, 20 negative cases, and
  hostile bounded archive/media/packet/log/time/record tests. Six fresh `EAS-001..006` sentinels
  passed two generations each, freshness, 12 references, 48 negatives, candidate-free capsule
  integration, and the merged CAP-02 unchanged static/dynamic flows. EAS-006 service lifecycle,
  deterministic checking, Docker cleanup, and absence proof passed with zero owned residue.
- Private CAP-04F admitted fresh owned `PWN-A`: V1–V3 plus two Tier-A calibration siblings passed
  independent and native references 5/5, 20 candidate negatives, 20 hostile native rejects, and
  exact/unique deterministic build, tool, and scanner gates. Exact-source real-OCI CAP-03 plus
  `ProcessChecker`/`OfflineBoard` rejected 2/2 wrong values, accepted 2/2 correct values, and reaped
  4/4 workers; all owned container, image, bank, scratch, nonregular, leak, and residue counts are
  zero. No historical material, internet, model, official Board, or scored solver was used.
- Early readiness quorum is admitted: 12 Tier-A difficult tasks across four categories and six
  families (`REV-A/B`, `CRY-A/B`, `FOR-A`, `PWN-A`), plus all six candidate-free sentinels. Private
  evidence remains owner-only; only closed version IDs, counts, and outcomes enter this public
  ledger. Stage 4 remains blocked only on reviewed/merged CAP-03 and CAP-05 plus a pre-outcome schema
  correction and immutable experiment registration.
