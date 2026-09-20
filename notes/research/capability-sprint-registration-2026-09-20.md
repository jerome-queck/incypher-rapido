# Capability sprint CAP-01 registration

**State:** frozen before capability outcomes. **Base source:**
`6aa26147c35fbc46affeeb77d93d6b88640564a8`, clean and equal to `origin/main`.

This checkpoint changes no production Board, target, model, proof, tool, scheduler, submission, or
instance behavior. It binds the public experiment contract and a private exact task-manifest
commitment. The official/private Board is out of scope for every sprint stage.

## Locked inputs

- Capability handoff archive: SHA-256
  `126af723c718faf9abe3a906f41ae155d49351674b6789721036324109ff8416`; bundled validator and
  independent integrity checks passed.
- Original urgent handoff: SHA-256
  `c00db23dea137afc9a2eb80256bd97403d6a71c01c6c975ab513100488b51fcc`; its urgent override and
  locked-results documents were read.
- Exact task manifest commitment: SHA-256
  `14a5dbd43fac8df0703b22a2cb258f458a7319c000f95e15b8ef5984a573981b`, covering 870 planned IDs:
  six sentinels, 18 calibration, 72 focused siblings, 36 routing, 18 held-out, and 720 capacity
  reserve IDs.
- R7 remains the accepted 15/15 post-run result with separate axes 15 / 0 / 42 / 2 / 0. H24 remains
  C/Q 24/11 versus 24/12 with `no_justified_change`. Neither is rerun, regraded, or treated as the
  difficult baseline.
- Issue #19 is closed under its owner-amended scope. Its original 19,800-second gate moved elsewhere
  and was not passed here.

## Source and runtime freeze

| Item | Frozen identity/result |
| --- | --- |
| Rapido base source | `6aa26147c35fbc46affeeb77d93d6b88640564a8`; clean; no source delta |
| Source archive | SHA-256 `194392eca8fe91eed26d7076648ac8eba0966468106992ccf25cd097b7c1a55f` |
| Dockerfile | SHA-256 `1010c573452e4698b13ff28fe4c1c8e83bf93ae355f5333f2bf70773c0f8eb29` |
| Offline wrapper Dockerfile | SHA-256 `4898cd29e5f4088752035a9e650057f02b0cedd0ce71678bdbc56174ed374e29` |
| Tool acceptance | SHA-256 `e23787d48001cd0318832ce5ce4d770eb198287d8e668c9c4e487d867bba4453` |
| Exact ARM64 image | `sha256:0eef1ceb74759bf64e9a89ca0dd1cf722bd1f6967a9b53666577164ee4d71c52` |
| Native client | image `codex-cli 0.154.0`; host `0.153.2` is incompatible with current strict flags |
| Design research | remote `main` matches `892c764ba65751af31c59386e27fdf05523e162e`; dirty later local checkout excluded |
| Historical workspace | remote `main` matches `463105313f82817d74cc0df67a648b3e698d3b10`; no scored-runner clone/mount |

The owner-only private parents, trust-zone roots, and synthetic removal probe passed the merged PR80
ownership/removability rule before container/provider work. Public artifacts record path classes,
not host paths.

The exact image's catalogue-only preflight returned exact matches, with no model turn or scored
task:

| Alias | Requested/effective model | Effort | Result |
| --- | --- | --- | --- |
| `DAYBREAK_XHIGH` | `gpt-daybreak-blue-latest` | `xhigh` | supported, exact |
| `LUNA_MAX` | `gpt-5.6-luna` | `max` | supported, exact |
| `LUNA_XHIGH` | `gpt-5.6-luna` | `xhigh` | supported, exact |

Fallback remains forbidden. A later mismatch or unavailable descriptor fails that arm.

## Competition deployability guard

The deployable competition path remains the existing packaged `rapido` CLI/container with Rapido
as PID 1, production Board authority validation, autonomous proof/submission policy, and the frozen
competition resource/scheduler contract. CAP-01 adds only standard-library artifact validation and
a CI-only JSON Schema test dependency. Offline Board/profile/runner work must remain directly
injected behind dedicated entry points; it must not alter production CLI construction, credentials,
origin checks, container entrypoint, or default runtime dependencies. The final integrated image and
production-compatible container contract are rechecked before held-out and capacity work.

## Frozen semantics

- Current mixed roster: Daybreak/xhigh lanes 0–1, Luna/max lane 2, Luna/xhigh lane 3; five active
  challenges, 20 lane admissions, one dynamic lease.
- Default scored task budget: 800 seconds × three episodes. Experiment wall and native usage caps
  are exact in `capability-sprint-experiments-v1.json`; null usage remains null.
- Primary difficult score includes every registered Tier A row, including failed, inconclusive,
  queued, and unstarted. The six sentinels are a separate `sentinel` tier and never inflate the
  difficult denominator.
- Candidate checking is private, deterministic, and once per exact unique candidate. Public output
  uses ordinals/counts only. Raw correctness, family capability, qualification projection, and
  actual independent verification remain separate.
- At cap: close admissions and model/tool/service work. Only a deterministic check already invoked
  for a pre-cap durable candidate may finish within 180 non-scoring seconds; exact outer cleanup has
  190 seconds.
- No offline result promotes production. Every proposed delta ends in an explicit human
  `approve`/`reject`/`defer` decision and rollback rule.

## Validation corrections

Independent handoff review found that the bundled receipt schema alone allowed duplicate sentinel
IDs, empty task/time-series arrays, cleanup success with residue, and a failed privacy scan. It also
classified sentinels as Tier A in the candidate manifest and represented conditional DAG gates as
undefined pseudo-nodes. CAP-01 resolves those interpretation hazards without rewriting the source
handoff:

- the public receipt schema requires a nonempty denominator, task rows, time series, exact six
  unique sentinels, privacy pass, and zero residue when cleanup passes;
- the receipt schema also freezes per-task lifecycle/model/checker fields, provider/tool failure
  counts, lossless per-attempt requested/effective model/effort/revision-build/native-client/usage
  rows, candidate/check/qualification/independent-verification events, timed tool and dynamic-service
  attempts, lane-time/global-active-wall measurement, cap/queue lifecycle,
  capability-versus-conversion classification, uncertainty/regression labels, and explicit human
  decision timestamps/rollback IDs;
- `rapido.offline_capability_schema` enforces the canonical registration commitment plus
  exact source/image/task/scheduler/roster bindings; Tier-A-only primary axes; and
  task/denominator/count, no-fallback, check-once, timing, cleanup, privacy, capacity, and other
  cross-field invariants not expressible in JSON Schema; consumers must run both layers;
- sentinel tier is frozen as `sentinel` for receipts;
- readiness/retention/held-out tokens are gates, not PR nodes.

## Ready DAG state

After CAP-01 review and merge/checkpoint, CAP-02 (offline Board), CAP-03 (private C/R/O boundary), and
CAP-05's pure receipt/controller design are ready. Scored work remains ineligible until the thin
Board sentinels pass and at least 12 fresh difficult Tier A tasks across four categories are
admitted with V1–V3 checks.

Open owner decisions remain: absolute production clock/submission reserve, private-bank lawful
provenance owner, any required descriptor failure, a sub-quorum pilot, 1.5× reservoir limitation,
held-out failure, routing production adoption, and per-delta final production decisions.
