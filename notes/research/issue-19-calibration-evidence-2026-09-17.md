# Issue #19 mixed-peer Board calibration — 2026-09-17

Status: completed calibration; issue #19 remains open.

This is sanitized evidence. It contains no candidate value or digest, credential, authority,
receipt, challenge description, raw model text, tool payload, or private host path.

## Registration and immutable execution

The exact protocol was registered in issue comment
[`#issuecomment-5700455647`](https://github.com/jerome-queck/incypher-rapido/issues/19#issuecomment-5700455647)
before the empty run state or workspace existed. The run used:

- main source `87712b886069cc1545febe04c38b2a1ca001493c`, merged in PR #35;
- ARM64 image
  `rapido@sha256:c932e2a80eb209a93eca42afec3b3b7b7d81f66fe495d8042e9848749799fd62`;
- green main CI run 35118024096 on Python 3.11/3.12 and Linux amd64/arm64;
- run ID `76fbb4d1c76f40a39b07b92777d8d349`;
- 1,800-second run budget; five active challenges; four peers per challenge; configured P20 lane
  admission cap; two episode maximum; one dynamic instance at a time;
- one Daybreak/xhigh Lead and Luna max/xhigh/max Specialists per initial challenge;
- typed challenge-scoped same-run memory, exact models, and no fallback;
- 60-second initial lanes, 10-second Board requests, 30-second instance readiness, and
  30-second cleanup;
- qualified submissions and managed instances enabled; no manual candidate relay or probe;
- container limits of 8 CPUs, 24 GiB RAM, 256 PIDs, and a 500-GiB configured workspace ceiling.

Model catalogue validation accepted Daybreak/xhigh, Luna/xhigh, and Luna/max before the run.
The current catalogue contained 15 executable challenges: nine dynamic and six standard. Four
independent pre-run GET-only rounds had established the documented HTTP-404 inactive shape for all
nine dynamic IDs with zero writes.

## Result

The container exited 0 after 711.076 seconds because all queued work was terminal; it was not
kept alive artificially to consume the 1,800-second ceiling. There was no operator steering,
fallback, or manual candidate handling.

- Initial coverage was 15/15. All 60 initial jobs and four routed Verifier jobs were admitted,
  started, and closed. The latest initial start sequence, 174, preceded the first retry start,
  180.
- Initial roster enforcement was exact: 15 Daybreak/xhigh Lead lanes, 15 Luna/xhigh Specialist
  lanes, and 30 Luna/max Specialist lanes. Four routed Verifier lanes used Daybreak/xhigh.
- Initial outcomes were 58 timeouts and two source-bound candidate proposals. Those two proposals
  agreed on one private identity. Four fresh-source Verifiers then agreed with each other on one
  different private identity. Cross-role identity matches and verified candidates were both zero,
  so the controller made no submission.
- Public result: 0 solved, 1 candidate, 14 errors, 0 unsupported, and 0 unsolved. Submissions and
  submission intents were both zero. No `already_solved` response was treated as validation.
- The disagreement route materially changed role, tactic, context, verification recipe, attempt
  budget, and deadline policy. Fourteen timeout routes were contained because no durable checkpoint
  authorized a changed retry. No unchanged route was retried.
- The run committed all 1,093 tool observations: 1,070 from timed-out turns and 23 from completed
  candidate turns; none was omitted. Of these, 994 were marked source-bound and 99 were not. This
  demonstrates that low host RAM was not evidence of unused tools.
- Typed-memory projection ran for all 64 lanes with zero rejected or invalid contexts, but exposed
  zero actual memory records: initial lanes had no earlier episode, and fresh Verifiers deliberately
  receive no peer memory. This calibration therefore does not establish a live solve benefit from
  cross-agent memory.
- Ten instance create/ready/cleanup cycles occurred because the dynamic Verifier revisited one of
  nine dynamic challenges. All nine durable instance rows ended `removed`.

The 60-second lane override successfully exercised scheduling and lifecycle but was falsified as a
solve-quality setting: 58/60 initial lanes timed out. It is calibration-only. The production and
future 19,800-second protocol retain the 1,800-second initial lane default.

## Resource and lifecycle audit

Operator-observed Docker samples reached 298.2 MiB RAM (1.24% of the 23.42-GiB container limit) and
84/256 PIDs. A separate operator-recorded 12-sample, 60-second window averaged 2.91% Docker CPU and
peaked at 9.58%; its peak RAM was 0.94% and peak PID count was 80. There was no observed OOM, quota,
rate-limit, or overload failure. The deliberately short lane deadline and serialized dynamic
lifecycle constrained this run; no RAM or quota failure was observed. Exact attempt intervals show
the configured P20 admission cap reached a peak of 16 concurrent lanes, so this run is not a measured
P20-saturation result.

SQLite integrity was `ok` with zero foreign-key violations. The exact run workspace contained zero
entries and zero bytes after exit. The surrounding work tree contained only one empty run directory
and one zero-byte lease. The exact container was absent.

Independent Daybreak/xhigh post-run audit performed two additional authenticated GET-only rounds
over all nine dynamic IDs. Every observation was coherent HTTP 404, `success=false`, with no
endpoint or timestamps; elapsed time was 11.322 seconds and writes were zero. It separately
confirmed nine removed instance rows, zero submission intents, zero submissions, zero candidate
verifications, empty workspaces, clean SQLite, and no container. No fallback was observed.

## Decision and remaining acceptance

The calibration passes the operational gate for full coverage, exact mixed routing, private
retention, fresh verification, tool use, serialized effects, and cleanup. It does not pass the
issue's solve-conversion gate: there was no current-run `correct` or deterministic verification.
The live memory benefit was also not exercised. No acceptance threshold is changed after this
result.

Issue #19 still requires owner authorization followed by the separately registered fresh
19,800-second run, at least one new HTTP-200 `correct`, cumulative autonomous solves of at least
four, proof that a new mechanism contributed to that solve, final-image recovery evidence, durable
sanitized acceptance evidence, exact-state deletion, and honest closure.
