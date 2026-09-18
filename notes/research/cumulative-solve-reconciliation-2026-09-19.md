# Cumulative solve reconciliation — 2026-09-19

The pre-run registration for `0fc6fe20cdaf4295a12bcf4855ebac52` named three historical
unique validated challenges and a target of four. That baseline was stale. A read-only
cross-run audit before scoring this run establishes a **lower bound of 14/15** distinct
qualifying IDs. The registration remains unchanged as the preregistered claim; this note
corrects the historical baseline. It does not include this run's results.

The counting rule in [README](../../README.md) counts a challenge once only from its source
run's `correct` verdict or independent deterministic verification. A generic
`already_solved` response and a later exact answer/method comparison do not add a
cumulative solve. Run lifecycle and provenance are separate axes.

| Source run/evidence | New distinct IDs | Cumulative distinct IDs | Evidence |
| --- | --- | ---: | --- |
| Issue #11 accepted source runs | `90,33,106` | 3 | [Issue #11 completion evidence](issue-11-completion-evidence-2026-09-16.md), especially the later owner amendment and ID list |
| Corrected calibration `b883988fb3ce434e97ee2512a29d788c` | `80,109` | 5 | [Corrected calibration evidence](issue-19-corrected-calibration-evidence-2026-09-17.md): two fresh HTTP-200 `correct` outcomes |
| One-hour diagnostic `2ef793e4bc314e41b4e4c3e844980a99` | `11,17,19,24,68,72` | 11 | [One-hour diagnostic evidence](issue-19-one-hour-diagnostic-evidence-2026-09-17.md): six HTTP-200 `correct` outcomes; later lifecycle failure does not reverse Board verdicts |
| Clean one-hour rerun `2e67273d58ce4f71bb6bf6eb930f65ee` | `7` | 12 | [One-hour rerun evidence](issue-19-one-hour-rerun-evidence-2026-09-17.md): one HTTP-200 `correct`; scoped Verifier IDs `33,80,109` were already counted |
| Recent R1 `772cad51...` | `15` | 13 | Owner-only private ZIP `incypher-rapido-issue19-2h-6754ec9-20260917t1541z-private.zip`, SHA-256 `29fee442dfdc8e9a9bb94323ebab0dfbcdbfb1ae4e635a7b6f190f506fac948f`, `state/rapido.sqlite3` |
| Recent R3 `acc97271...` | `42` | **14** | Owner-only private ZIP `incypher-rapido-issue19-2h-d52e986-20260917t2136z-failed-private.zip`, SHA-256 `071d927ac7375741e355b707b12bf2d2c9ae32bc51f3fd45d080a47603028a13`, embedded `state/rapido.sqlite3` |

The validated pre-run ID set is `7,11,15,17,19,24,33,42,68,72,80,90,106,109`.
ID `94` is absent. An earlier external replay described a Zip candidate as correct, but a
later exact-answer check contradicted the R4 candidate. R5's exact post-run Zip candidate
is a practice-score result, not a qualifying source-run Board/Verifier result.

## Evidence tiers and limits

R1 and R3 have raw archived SQLite/proof evidence still in Downloads. Each contains exactly
one `correct` row with HTTP 200 and a matching durable intent, same-run proposal, final
candidate proof, and terminal source attempt. R1's producer manifest is complete at
27/27 observations; R3's at 384/384. Both use the source-bound observation recipe with
zero omission. R1 ended at deadline. R3 later failed Board transport; its `correct` verdict
predated that failure. Neither later event invalidates the verdict.

The other 12 IDs are supported by merged sanitized run ledgers. Their raw state is no longer
in Downloads after the documented cleanup, so this audit cannot replay their candidate-level
SQL. The issue #11 three were explicitly accepted in its later owner amendment. R1 has a
legacy unscoped Verifier record for ID `33`; it adds no strict validation and is a duplicate.
No available R2, R4, R5, or R6 archive adds a qualifying ID.

The `>=4` cumulative target in the current full-run registration was already met before that
run. Report it as a preregistered but non-discriminating target. Report current-run validation
and the marginal new IDs separately, using current-material scoped Verifier evidence and
qualified source-run `correct` only. Do not infer a new solve from an `already_solved` verdict.
